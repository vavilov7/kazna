import pytest

from kazna.cipher import DecryptionError
from kazna.identity import Identity
from kazna.nip04 import Nip04Cipher


def test_round_trip_between_two_keys():
    alice, bob = Identity.generate(), Identity.generate()
    payload = Nip04Cipher.between(alice, bob.pubkey).encrypt('{"method":"ping","note":"ñ ✓"}')
    assert Nip04Cipher.matches(payload)
    assert Nip04Cipher.between(bob, alice.pubkey).decrypt(payload) == '{"method":"ping","note":"ñ ✓"}'


def test_known_payload():
    # Expected value from: printf hello | openssl enc -aes-256-cbc -K 0001…1f -iv 00…00 | base64
    cipher = Nip04Cipher(bytes(range(32)))
    assert cipher.encrypt("hello", iv=bytes(16)) == "kWhEh8NMNFbrTpAc74hKHg==?iv=AAAAAAAAAAAAAAAAAAAAAA=="


@pytest.mark.parametrize("payload", ["no-iv-here", "abc?iv=def", "AAAA?iv=AAAAAAAAAAAAAAAAAAAAAA=="])
def test_rejects_malformed_payloads(payload):
    with pytest.raises(DecryptionError):
        Nip04Cipher(bytes(32)).decrypt(payload)


def test_wrong_key_fails():
    alice, bob, eve = Identity.generate(), Identity.generate(), Identity.generate()
    payload = Nip04Cipher.between(alice, bob.pubkey).encrypt("secret")
    with pytest.raises(DecryptionError):
        Nip04Cipher.between(eve, alice.pubkey).decrypt(payload)
