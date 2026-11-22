"""Official NIP-44 v2 vectors (paulmillr/nip44, sha256 269ed0f6… as listed in NIP-44)."""

import hashlib
import json
from pathlib import Path

import pytest

from kazna.cipher import DecryptionError
from kazna.identity import Identity, IdentityError
from kazna.nip44 import Nip44Cipher

VECTORS = json.loads((Path(__file__).parent / "vectors" / "nip44.vectors.json").read_text())["v2"]
VALID, INVALID = VECTORS["valid"], VECTORS["invalid"]


@pytest.mark.parametrize("case", VALID["get_conversation_key"])
def test_conversation_key(case):
    cipher = Nip44Cipher.between(Identity.from_secret(case["sec1"]), case["pub2"])
    assert cipher.conversation_key.hex() == case["conversation_key"]


@pytest.mark.parametrize("case", VALID["get_message_keys"]["keys"])
def test_message_keys(case):
    cipher = Nip44Cipher(bytes.fromhex(VALID["get_message_keys"]["conversation_key"]))
    chacha_key, chacha_nonce, hmac_key = cipher.message_keys(bytes.fromhex(case["nonce"]))
    assert (chacha_key.hex(), chacha_nonce.hex(), hmac_key.hex()) == (
        case["chacha_key"], case["chacha_nonce"], case["hmac_key"])


@pytest.mark.parametrize("length, padded", VALID["calc_padded_len"])
def test_padded_length(length, padded):
    assert Nip44Cipher.padded_length(length) == padded


@pytest.mark.parametrize("case", VALID["encrypt_decrypt"])
def test_encrypt_decrypt(case):
    sender, receiver = Identity.from_secret(case["sec1"]), Identity.from_secret(case["sec2"])
    cipher = Nip44Cipher.between(sender, receiver.pubkey)
    assert cipher.conversation_key.hex() == case["conversation_key"]
    assert cipher.encrypt(case["plaintext"], bytes.fromhex(case["nonce"])) == case["payload"]
    assert Nip44Cipher.between(receiver, sender.pubkey).decrypt(case["payload"]) == case["plaintext"]


@pytest.mark.parametrize("case", VALID["encrypt_decrypt_long_msg"])
def test_long_messages(case):
    cipher = Nip44Cipher(bytes.fromhex(case["conversation_key"]))
    plaintext = case["pattern"] * case["repeat"]
    assert hashlib.sha256(plaintext.encode()).hexdigest() == case["plaintext_sha256"]
    payload = cipher.encrypt(plaintext, bytes.fromhex(case["nonce"]))
    assert hashlib.sha256(payload.encode()).hexdigest() == case["payload_sha256"]
    assert cipher.decrypt(payload) == plaintext


@pytest.mark.parametrize("length", INVALID["encrypt_msg_lengths"])
def test_rejects_invalid_plaintext_length(length):
    with pytest.raises(ValueError):
        Nip44Cipher(bytes(32)).encrypt("a" * length)


@pytest.mark.parametrize("case", INVALID["get_conversation_key"], ids=lambda c: c["note"])
def test_rejects_invalid_keys(case):
    with pytest.raises(IdentityError):
        Nip44Cipher.between(Identity.from_secret(case["sec1"]), case["pub2"])


@pytest.mark.parametrize("case", INVALID["decrypt"], ids=lambda c: c["note"])
def test_rejects_invalid_payloads(case):
    with pytest.raises(DecryptionError):
        Nip44Cipher(bytes.fromhex(case["conversation_key"])).decrypt(case["payload"])
