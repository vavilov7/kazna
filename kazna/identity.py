from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from coincurve import PrivateKey, PublicKey

from . import nip19


class IdentityError(Exception):
    pass


def short_key(pubkey: str) -> str:
    return f"{pubkey[:8]}…{pubkey[-4:]}"


class Identity:
    """A Nostr keypair: a secp256k1 secret key and its x-only public key (BIP-340)."""

    def __init__(self, key: PrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> Identity:
        return cls(PrivateKey())

    @classmethod
    def from_secret(cls, value: str) -> Identity:
        """Accepts an nsec1… string or the raw secret as 64 hex characters."""
        value = value.strip()
        try:
            if value.lower().startswith("nsec1"):
                return cls(PrivateKey(nip19.decode("nsec", value)))
            if re.fullmatch(r"[0-9a-fA-F]{64}", value):
                return cls(PrivateKey(bytes.fromhex(value)))
        except ValueError as exc:
            raise IdentityError(f"invalid secret key: {exc}") from exc
        raise IdentityError("expected an nsec1… string or 64 hex characters")

    @property
    def pubkey(self) -> str:
        return self._key.public_key_xonly.format().hex()

    @property
    def npub(self) -> str:
        return nip19.encode("npub", bytes.fromhex(self.pubkey))

    @property
    def nsec(self) -> str:
        return nip19.encode("nsec", self._key.secret)

    def sign(self, digest: bytes) -> bytes:
        return self._key.sign_schnorr(digest, os.urandom(32))

    def shared_x(self, peer_pubkey: str) -> bytes:
        """ECDH with a peer's x-only key. Returns the raw x coordinate, unhashed,
        which is what NIP-04 and NIP-44 expect (unlike coincurve's ecdh())."""
        try:
            peer = PublicKey(b"\x02" + bytes.fromhex(peer_pubkey))
        except ValueError as exc:
            raise IdentityError(f"invalid public key {peer_pubkey!r}") from exc
        return peer.multiply(self._key.secret).format(compressed=True)[1:]


class IdentityStore:
    """One directory per identity under `root`, each holding a key.json file."""

    KEY_FILE = "key.json"
    NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")

    def __init__(self, root: Path):
        self.root = root

    def path_for(self, name: str) -> Path:
        # Names become directory names, so anything that could escape `root` is rejected.
        if not self.NAME_PATTERN.fullmatch(name):
            raise IdentityError(f"invalid identity name {name!r} (use letters, digits, '-' or '_')")
        return self.root / name

    def save(self, name: str, identity: Identity) -> None:
        directory = self.path_for(name)
        key_file = directory / self.KEY_FILE
        if key_file.exists():
            raise IdentityError(f"identity {name!r} already exists")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = {
            "name": name,
            "pubkey": identity.pubkey,
            "npub": identity.npub,
            "nsec": identity.nsec,
            "created_at": int(time.time()),
        }
        # Opened with 0600 from the start so the secret is never readable by others.
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def load(self, name: str) -> Identity:
        key_file = self.path_for(name) / self.KEY_FILE
        if not key_file.exists():
            raise IdentityError(f"identity {name!r} not found")
        data = json.loads(key_file.read_text())
        return Identity.from_secret(data["nsec"])
