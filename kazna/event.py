from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar

from coincurve import PublicKeyXOnly

if TYPE_CHECKING:
    from .identity import Identity


@dataclass
class Event:
    """A Nostr event (NIP-01). `pubkey`, `id` and `sig` are filled in by sign()."""

    TEXT_NOTE: ClassVar[int] = 1

    kind: int
    content: str
    tags: list[list[str]] = field(default_factory=list)
    created_at: int = field(default_factory=lambda: int(time.time()))
    pubkey: str = ""
    id: str = ""
    sig: str = ""

    @classmethod
    def text_note(cls, content: str) -> Event:
        return cls(kind=cls.TEXT_NOTE, content=content)

    @classmethod
    def from_dict(cls, data: object) -> Event:
        """Builds an event from untrusted JSON. `pubkey`, `id` and `sig` may be absent (unsigned)."""
        if not isinstance(data, dict):
            raise ValueError("event must be a JSON object")
        kind, content = data.get("kind"), data.get("content", "")
        tags, created_at = data.get("tags", []), data.get("created_at")
        if not _is_int(kind) or not 0 <= kind <= 65535:
            raise ValueError("invalid kind")
        if not isinstance(content, str):
            raise ValueError("invalid content")
        if not isinstance(tags, list) or not all(
                isinstance(tag, list) and all(isinstance(v, str) for v in tag) for tag in tags):
            raise ValueError("invalid tags")
        if not _is_int(created_at):
            raise ValueError("invalid created_at")
        signature_fields = {name: data.get(name, "") for name in ("pubkey", "id", "sig")}
        if not all(isinstance(value, str) for value in signature_fields.values()):
            raise ValueError("invalid pubkey, id or sig")
        return cls(kind=kind, content=content, tags=tags, created_at=created_at, **signature_fields)

    def serialize(self) -> bytes:
        # Canonical NIP-01 form: compact JSON array, UTF-8, non-ASCII left unescaped.
        payload = [0, self.pubkey, self.created_at, self.kind, self.tags, self.content]
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()

    def compute_id(self) -> str:
        return hashlib.sha256(self.serialize()).hexdigest()

    def sign(self, identity: Identity) -> Event:
        self.pubkey = identity.pubkey
        self.id = self.compute_id()
        self.sig = identity.sign(bytes.fromhex(self.id)).hex()
        return self

    def verify(self) -> bool:
        if not self.sig or self.id != self.compute_id():
            return False
        try:
            key = PublicKeyXOnly(bytes.fromhex(self.pubkey))
            return key.verify(bytes.fromhex(self.sig), bytes.fromhex(self.id))
        except ValueError:
            return False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
