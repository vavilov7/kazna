"""NIP-44 v2 encryption: ChaCha20 + HMAC-SHA256, keys derived with HKDF, padded lengths."""

from __future__ import annotations

import base64
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .cipher import Cipher, DecryptionError
from .identity import Identity


class Nip44Cipher(Cipher):
    scheme = "nip44"
    VERSION = 2
    SALT = b"nip44-v2"
    MAX_PLAINTEXT = 65535

    def __init__(self, conversation_key: bytes):
        self.conversation_key = conversation_key

    @classmethod
    def between(cls, local: Identity, peer_pubkey: str) -> Nip44Cipher:
        # HKDF-extract is a single HMAC with the salt as key.
        return cls(hmac.digest(cls.SALT, local.shared_x(peer_pubkey), "sha256"))

    def message_keys(self, nonce: bytes) -> tuple[bytes, bytes, bytes]:
        """(chacha_key, chacha_nonce, hmac_key) for one message."""
        keys = HKDFExpand(SHA256(), 76, nonce).derive(self.conversation_key)
        return keys[:32], keys[32:44], keys[44:]

    def encrypt(self, plaintext: str, nonce: bytes | None = None) -> str:
        nonce = nonce or os.urandom(32)
        chacha_key, chacha_nonce, hmac_key = self.message_keys(nonce)
        ciphertext = self._chacha20(chacha_key, chacha_nonce, self._pad(plaintext.encode()))
        mac = hmac.digest(hmac_key, nonce + ciphertext, "sha256")
        return base64.b64encode(bytes([self.VERSION]) + nonce + ciphertext + mac).decode()

    def decrypt(self, payload: str) -> str:
        if not payload or payload[0] == "#":
            raise DecryptionError("unsupported encryption version")
        if not 132 <= len(payload) <= 87472:
            raise DecryptionError("invalid payload size")
        try:
            data = base64.b64decode(payload, validate=True)
        except ValueError as exc:
            raise DecryptionError("invalid base64") from exc
        if not 99 <= len(data) <= 65603:
            raise DecryptionError("invalid data size")
        if data[0] != self.VERSION:
            raise DecryptionError(f"unsupported encryption version {data[0]}")

        nonce, ciphertext, mac = data[1:33], data[33:-32], data[-32:]
        chacha_key, chacha_nonce, hmac_key = self.message_keys(nonce)
        if not hmac.compare_digest(mac, hmac.digest(hmac_key, nonce + ciphertext, "sha256")):
            raise DecryptionError("invalid MAC")
        try:
            return self._unpad(self._chacha20(chacha_key, chacha_nonce, ciphertext)).decode()
        except UnicodeDecodeError as exc:
            raise DecryptionError("plaintext is not UTF-8") from exc

    @staticmethod
    def padded_length(length: int) -> int:
        if length <= 32:
            return 32
        next_power = 1 << (length - 1).bit_length()
        chunk = 32 if next_power <= 256 else next_power // 8
        return chunk * ((length - 1) // chunk + 1)

    @classmethod
    def _pad(cls, data: bytes) -> bytes:
        if not 1 <= len(data) <= cls.MAX_PLAINTEXT:
            raise ValueError(f"plaintext must be 1 to {cls.MAX_PLAINTEXT} bytes")
        padding = cls.padded_length(len(data)) - len(data)
        return len(data).to_bytes(2, "big") + data + bytes(padding)

    @classmethod
    def _unpad(cls, padded: bytes) -> bytes:
        length = int.from_bytes(padded[:2], "big")
        data = padded[2:2 + length]
        if length == 0 or len(data) != length or len(padded) != 2 + cls.padded_length(length):
            raise DecryptionError("invalid padding")
        return data

    @staticmethod
    def _chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
        # cryptography takes a 16-byte nonce: a 4-byte little-endian block counter (0) + the 12-byte nonce.
        return CryptoCipher(ChaCha20(key, bytes(4) + nonce), mode=None).encryptor().update(data)
