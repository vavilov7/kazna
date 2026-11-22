"""NIP-04 encryption: AES-256-CBC keyed by the raw ECDH x coordinate.

Deprecated in favor of NIP-44 (no authentication, leaks length), but Stacker News's
NIP-46 client (NDK 2.12) still sends its requests with it.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7

from .cipher import Cipher, DecryptionError
from .identity import Identity


class Nip04Cipher(Cipher):
    scheme = "nip04"
    IV_SEPARATOR = "?iv="

    def __init__(self, key: bytes):
        self.key = key

    @classmethod
    def between(cls, local: Identity, peer_pubkey: str) -> Nip04Cipher:
        return cls(local.shared_x(peer_pubkey))

    @classmethod
    def matches(cls, payload: str) -> bool:
        return cls.IV_SEPARATOR in payload

    def encrypt(self, plaintext: str, iv: bytes | None = None) -> str:
        iv = iv or os.urandom(16)
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext.encode()) + padder.finalize()
        encryptor = CryptoCipher(AES(self.key), CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return f"{base64.b64encode(ciphertext).decode()}{self.IV_SEPARATOR}{base64.b64encode(iv).decode()}"

    def decrypt(self, payload: str) -> str:
        try:
            encoded_ciphertext, encoded_iv = payload.split(self.IV_SEPARATOR)
            ciphertext = base64.b64decode(encoded_ciphertext, validate=True)
            iv = base64.b64decode(encoded_iv, validate=True)
            decryptor = CryptoCipher(AES(self.key), CBC(iv)).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            return (unpadder.update(padded) + unpadder.finalize()).decode()
        except ValueError as exc:
            raise DecryptionError(f"invalid nip04 payload: {exc}") from exc
