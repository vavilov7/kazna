from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

if TYPE_CHECKING:
    from .identity import Identity


class DecryptionError(Exception):
    pass


class Cipher(ABC):
    """Encrypts text between a local key and one peer key."""

    scheme: ClassVar[str]

    @classmethod
    @abstractmethod
    def between(cls, local: Identity, peer_pubkey: str) -> Cipher: ...

    @abstractmethod
    def encrypt(self, plaintext: str) -> str: ...

    @abstractmethod
    def decrypt(self, payload: str) -> str: ...
