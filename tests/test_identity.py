import pytest

from kazna import nip19
from kazna.event import Event
from kazna.identity import Identity, IdentityError, IdentityStore

# NIP-19 spec examples
SECRET_HEX = "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
NSEC = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
NPUB = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
NPUB_HEX = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"


def test_nip19_vectors():
    assert Identity.from_secret(SECRET_HEX).nsec == NSEC
    assert Identity.from_secret(NSEC).nsec == NSEC
    assert nip19.encode("npub", bytes.fromhex(NPUB_HEX)) == NPUB
    assert nip19.decode("npub", NPUB).hex() == NPUB_HEX


@pytest.mark.parametrize("value", ["", "nsec1invalid", "zz" * 32, "00" * 32])
def test_rejects_invalid_secrets(value):
    with pytest.raises(IdentityError):
        Identity.from_secret(value)


def test_store_round_trip_and_permissions(tmp_path):
    store = IdentityStore(tmp_path)
    identity = Identity.generate()
    store.save("alice", identity)
    assert store.load("alice").pubkey == identity.pubkey
    assert (tmp_path / "alice" / "key.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(IdentityError):
        store.save("alice", Identity.generate())


@pytest.mark.parametrize("name", ["../evil", "a/b", ".hidden", ""])
def test_store_rejects_unsafe_names(tmp_path, name):
    with pytest.raises(IdentityError):
        IdentityStore(tmp_path).path_for(name)


def test_event_sign_and_verify():
    event = Event.text_note('marri "marri" mapu ñ\n✓').sign(Identity.generate())
    assert event.verify()
    event.content += "x"
    assert not event.verify()


def test_event_from_dict_round_trip():
    event = Event.text_note("hi").sign(Identity.generate())
    assert Event.from_dict(event.to_dict()).verify()


@pytest.mark.parametrize("data", [
    [],
    {"kind": "1", "content": "", "tags": [], "created_at": 1},
    {"kind": 1, "content": 5, "tags": [], "created_at": 1},
    {"kind": 1, "content": "", "tags": [["a", 1]], "created_at": 1},
    {"kind": 1, "content": "", "tags": []},
])
def test_event_from_dict_rejects_bad_fields(data):
    with pytest.raises(ValueError):
        Event.from_dict(data)
