"""NIP-46 remote signing.

`RemoteSigner` implements the methods and holds no I/O; `Bunker` carries it over relays
as encrypted kind 24133 events.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlencode

from .approval import Approver
from .cipher import Cipher, DecryptionError
from .event import Event
from .identity import Identity, IdentityError, short_key
from .nip04 import Nip04Cipher
from .nip44 import Nip44Cipher
from .relay import PublishResult, RelayPool

log = logging.getLogger(__name__)

KIND_NOSTR_CONNECT = 24133


class SignerError(Exception):
    """A refused request; the message goes back to the client as `error`."""


@dataclass(frozen=True)
class BunkerUrl:
    signer_pubkey: str
    relays: tuple[str, ...]
    secret: str

    def __str__(self) -> str:
        query = urlencode([("relay", relay) for relay in self.relays] + [("secret", self.secret)])
        return f"bunker://{self.signer_pubkey}?{query}"


@dataclass
class Request:
    id: str
    method: str
    params: list[str]

    @classmethod
    def parse(cls, text: str) -> Request:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("request must be a JSON object")
        request_id, method, params = data.get("id"), data.get("method"), data.get("params", [])
        if not isinstance(request_id, str) or not isinstance(method, str):
            raise ValueError("request needs string id and method")
        if not isinstance(params, list) or not all(isinstance(p, str) for p in params):
            raise ValueError("params must be a list of strings")
        return cls(request_id, method, params)


@dataclass
class Response:
    id: str
    result: str = ""
    error: str | None = None

    def to_json(self) -> str:
        body = {"id": self.id, "result": self.result}
        if self.error is not None:
            body["error"] = self.error
        return json.dumps(body, ensure_ascii=False)


class RemoteSigner:
    """Signs with the user's key on behalf of connected clients.

    The signer has its own transport key (`signer_key`), separate from the user's identity:
    clients talk to the signer key and learn the user's pubkey through `get_public_key`.
    A client connects once with the current secret; each secret works for one connection.
    """

    def __init__(self, user: Identity, approver: Approver, signer_key: Identity | None = None):
        self.user = user
        self.approver = approver
        self.signer_key = signer_key or Identity.generate()
        self.secret = secrets.token_hex(16)
        self.clients: set[str] = set()
        self._methods = {
            "connect": self._connect,
            "get_public_key": self._get_public_key,
            "sign_event": self._sign_event,
            "ping": self._ping,
            "logout": self._logout,
        }

    async def handle(self, client: str, request: Request) -> Response:
        method = self._methods.get(request.method)
        try:
            if method is None:
                raise SignerError(f"unsupported method: {request.method}")
            if request.method != "connect" and client not in self.clients:
                raise SignerError("not connected")
            return Response(request.id, await method(client, request.params))
        except SignerError as exc:
            return Response(request.id, error=str(exc))

    async def _connect(self, client: str, params: list[str]) -> str:
        target = params[0] if params else ""
        # The spec puts the signer pubkey first; NDK 2.12 (Stacker News) sends "" instead.
        if target not in ("", self.signer_key.pubkey, self.user.pubkey):
            raise SignerError("connect is addressed to a different signer")
        if client in self.clients:
            return "ack"
        given = params[1] if len(params) > 1 else ""
        if not hmac.compare_digest(given.encode(), self.secret.encode()):
            raise SignerError("invalid or already used secret")
        self.clients.add(client)
        self.secret = secrets.token_hex(16)
        # NDK 2.12 accepts only "ack"; newer spec revisions also allow echoing the secret.
        return "ack"

    async def _get_public_key(self, client: str, params: list[str]) -> str:
        return self.user.pubkey

    async def _sign_event(self, client: str, params: list[str]) -> str:
        try:
            event = Event.from_dict(json.loads(params[0]))
        except (IndexError, ValueError) as exc:
            raise SignerError(f"invalid event: {exc}") from exc
        if event.pubkey and event.pubkey != self.user.pubkey:
            raise SignerError("event pubkey is not this signer's user")
        if not await self.approver.approve(client, event):
            raise SignerError("rejected by the user")
        event.sign(self.user)
        return json.dumps(event.to_dict(), ensure_ascii=False)

    async def _ping(self, client: str, params: list[str]) -> str:
        return "pong"

    async def _logout(self, client: str, params: list[str]) -> str:
        self.clients.discard(client)
        return "ack"


class Bunker:
    """Serves a RemoteSigner over relays: listens for kind 24133 events tagged with the
    signer key, decrypts each request, and publishes the encrypted response."""

    DEFAULT_RELAYS = ("wss://nos.lol", "wss://relay.primal.net")

    def __init__(self, signer: RemoteSigner, relays: Iterable[str],
                 on_connect: Callable[[str, BunkerUrl], None] | None = None):
        self.signer = signer
        self.relays = tuple(relays)
        self.on_connect = on_connect
        self._replies: set[asyncio.Task] = set()

    @property
    def url(self) -> BunkerUrl:
        return BunkerUrl(self.signer.signer_key.pubkey, self.relays, self.signer.secret)

    async def serve(self) -> None:
        subscription = {
            "kinds": [KIND_NOSTR_CONNECT],
            "#p": [self.signer.signer_key.pubkey],
            "since": int(time.time()),
        }
        async with RelayPool(self.relays, [subscription]) as pool:
            async for relay, raw in pool.events():
                await self._handle(pool, relay, raw)

    async def _handle(self, pool: RelayPool, relay: str, raw: dict) -> None:
        try:
            envelope = Event.from_dict(raw)
        except ValueError as exc:
            log.warning("dropped malformed event from %s: %s", relay, exc)
            return
        if envelope.kind != KIND_NOSTR_CONNECT or not envelope.verify():
            log.warning("dropped invalid event %s from %s", envelope.id[:8], relay)
            return

        client = envelope.pubkey
        # NIP-04 payloads carry "?iv="; anything else is NIP-44. Replies use the request's scheme.
        cipher_class: type[Cipher] = Nip04Cipher if Nip04Cipher.matches(envelope.content) else Nip44Cipher
        try:
            cipher = cipher_class.between(self.signer.signer_key, client)
            request = Request.parse(cipher.decrypt(envelope.content))
        except (DecryptionError, IdentityError, ValueError) as exc:
            log.warning("dropped unreadable request from %s: %s", short_key(client), exc)
            return

        log.info("%s from %s (%s)", request.method, short_key(client), cipher.scheme)
        secret_before = self.signer.secret
        response = await self.signer.handle(client, request)
        if response.error:
            log.info("  refused: %s", response.error)

        reply = Event(
            kind=KIND_NOSTR_CONNECT,
            content=cipher.encrypt(response.to_json()),
            tags=[["p", client]],
        ).sign(self.signer.signer_key)
        # Published in the background so one slow relay doesn't hold up the next request.
        task = asyncio.create_task(self._publish_reply(pool, reply))
        self._replies.add(task)
        task.add_done_callback(self._replies.discard)

        if self.signer.secret != secret_before and self.on_connect:
            self.on_connect(client, self.url)

    @staticmethod
    async def _publish_reply(pool: RelayPool, reply: Event) -> None:
        results: list[PublishResult] = await pool.publish(reply)
        if not any(r.accepted for r in results):
            log.warning("reply %s was not accepted by any relay: %s", reply.id[:8],
                        "; ".join(f"{r.relay} {r.message}" for r in results))
