from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import WebSocketException

from .event import Event

log = logging.getLogger(__name__)


@dataclass
class PublishResult:
    relay: str
    accepted: bool
    message: str = ""


class RelayConnection:
    """One relay: keeps a websocket open, reconnecting with backoff, re-sends the
    subscription on every connect, and matches OK replies to published events."""

    SUBSCRIPTION_ID = "kazna"
    MAX_BACKOFF = 60.0

    def __init__(self, url: str, filters: list[dict], inbox: asyncio.Queue, timeout: float):
        self.url = url
        self.filters = filters
        self.inbox = inbox
        self.timeout = timeout
        self.last_error = ""
        self._ws: ClientConnection | None = None
        self._connected = asyncio.Event()
        self._pending: dict[str, asyncio.Future[PublishResult]] = {}

    async def run(self) -> None:
        backoff = 1.0
        while True:
            try:
                async with connect(self.url, open_timeout=self.timeout, close_timeout=2) as ws:
                    await self._on_open(ws)
                    backoff = 1.0
                    async for raw in ws:
                        self._dispatch(raw)
                self.last_error = "connection closed by relay"
            except (OSError, TimeoutError, WebSocketException) as exc:
                self.last_error = str(exc) or type(exc).__name__
            finally:
                self._on_close()
            log.info("%s: %s, reconnecting in %.0fs", self.url, self.last_error, backoff)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.MAX_BACKOFF)

    async def publish(self, event: Event) -> PublishResult:
        """Waits up to `timeout` for a connection and for the relay's OK."""
        try:
            async with asyncio.timeout(self.timeout):
                await self._connected.wait()
                future = asyncio.get_running_loop().create_future()
                self._pending[event.id] = future
                await self._ws.send(json.dumps(["EVENT", event.to_dict()], ensure_ascii=False))
                return await future
        except TimeoutError:
            return PublishResult(self.url, False, self.last_error or "timed out")
        except WebSocketException as exc:
            return PublishResult(self.url, False, str(exc))
        finally:
            self._pending.pop(event.id, None)

    async def _on_open(self, ws: ClientConnection) -> None:
        self._ws = ws
        if self.filters:
            await ws.send(json.dumps(["REQ", self.SUBSCRIPTION_ID, *self.filters]))
        self.last_error = ""
        self._connected.set()
        log.info("%s: connected", self.url)

    def _on_close(self) -> None:
        self._ws = None
        self._connected.clear()
        for future in self._pending.values():
            if not future.done():
                future.set_result(PublishResult(self.url, False, "connection lost"))

    def _dispatch(self, raw: str | bytes) -> None:
        try:
            message = json.loads(raw)
        except ValueError:
            return
        match message:
            case ["EVENT", _, dict() as event]:
                self.inbox.put_nowait((self.url, event))
            case ["OK", str() as event_id, accepted, *rest]:
                future = self._pending.get(event_id)
                if future and not future.done():
                    future.set_result(PublishResult(self.url, bool(accepted), str(rest[0]) if rest else ""))
            case ["CLOSED", _, *rest]:
                log.warning("%s: subscription closed by relay: %s", self.url, rest[0] if rest else "")
            case ["NOTICE", *rest]:
                log.info("%s: notice: %s", self.url, rest[0] if rest else "")


class RelayPool:
    """Connections to several relays sharing one inbox. Use as `async with`; events
    received on more than one relay are yielded once."""

    DEFAULT_RELAYS = ("wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net")
    SEEN_LIMIT = 10_000

    def __init__(self, urls: Iterable[str], filters: list[dict] | None = None, timeout: float = 10.0):
        self._inbox: asyncio.Queue[tuple[str, dict]] = asyncio.Queue()
        self.connections = [RelayConnection(url, filters or [], self._inbox, timeout) for url in urls]
        self._tasks: list[asyncio.Task] = []
        self._seen: OrderedDict[str, None] = OrderedDict()

    async def __aenter__(self) -> RelayPool:
        self._tasks = [asyncio.create_task(c.run()) for c in self.connections]
        return self

    async def __aexit__(self, *exc_info) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def publish(self, event: Event) -> list[PublishResult]:
        return list(await asyncio.gather(*(c.publish(event) for c in self.connections)))

    async def events(self) -> AsyncIterator[tuple[str, dict]]:
        """Yields (relay_url, raw_event) for each new event matching the filters."""
        while True:
            relay, event = await self._inbox.get()
            event_id = event.get("id")
            if event_id in self._seen:
                continue
            self._seen[event_id] = None
            if len(self._seen) > self.SEEN_LIMIT:
                self._seen.popitem(last=False)
            yield relay, event
