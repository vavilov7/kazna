import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from kazna.approval import Approver, AutoApprover
from kazna.event import Event
from kazna.identity import Identity
from kazna.nip04 import Nip04Cipher
from kazna.nip44 import Nip44Cipher
from kazna.nip46 import KIND_NOSTR_CONNECT, Bunker, RemoteSigner, Request
from kazna.relay import PublishResult

CLIENT = Identity.generate().pubkey
AUTH_EVENT = {"kind": 27235, "created_at": 1_700_000_000, "content": "Stacker News Authentication",
              "tags": [["challenge", "k1"], ["u", "https://stacker.news"], ["method", "GET"]]}


class RejectAll(Approver):
    async def approve(self, client, event):
        return False


def call(signer: RemoteSigner, method: str, *params: str, client: str = CLIENT):
    return asyncio.run(signer.handle(client, Request("1", method, list(params))))


@pytest.fixture
def signer():
    return RemoteSigner(Identity.generate(), AutoApprover())


def test_signer_key_is_separate_from_user_key(signer):
    assert signer.signer_key.pubkey != signer.user.pubkey


@pytest.mark.parametrize("first_param", ["", "signer", "user"])
def test_connect_accepts_ndk_and_spec_first_params(signer, first_param):
    target = {"": "", "signer": signer.signer_key.pubkey, "user": signer.user.pubkey}[first_param]
    assert call(signer, "connect", target, signer.secret).result == "ack"


def test_connect_rejects_wrong_secret_and_other_signer(signer):
    assert call(signer, "connect", "", "wrong").error
    assert call(signer, "connect", Identity.generate().pubkey, signer.secret).error
    assert CLIENT not in signer.clients


def test_secret_is_single_use(signer):
    secret = signer.secret
    assert call(signer, "connect", "", secret).result == "ack"
    assert signer.secret != secret
    assert call(signer, "connect", "", secret, client=Identity.generate().pubkey).error


def test_requests_before_connect_are_refused(signer):
    for method in ("get_public_key", "sign_event", "ping"):
        assert call(signer, method).error == "not connected"


def test_unknown_method(signer):
    assert call(signer, "nip44_decrypt", "x", "y").error == "unsupported method: nip44_decrypt"


def test_login_flow_signs_with_user_key(signer):
    call(signer, "connect", "", signer.secret)
    assert call(signer, "get_public_key").result == signer.user.pubkey
    signed = Event.from_dict(json.loads(call(signer, "sign_event", json.dumps(AUTH_EVENT)).result))
    assert signed.verify()
    assert signed.pubkey == signer.user.pubkey
    assert signed.tags[0] == ["challenge", "k1"]
    assert call(signer, "ping").result == "pong"


def test_sign_event_rejections():
    signer = RemoteSigner(Identity.generate(), RejectAll())
    call(signer, "connect", "", signer.secret)
    assert call(signer, "sign_event", json.dumps(AUTH_EVENT)).error == "rejected by the user"
    assert call(signer, "sign_event", "not json").error.startswith("invalid event")
    foreign = dict(AUTH_EVENT, pubkey=Identity.generate().pubkey)
    assert call(signer, "sign_event", json.dumps(foreign)).error == "event pubkey is not this signer's user"


def test_logout_disconnects(signer):
    call(signer, "connect", "", signer.secret)
    assert call(signer, "logout").result == "ack"
    assert call(signer, "ping").error == "not connected"


def test_bunker_url_format(signer):
    url = Bunker(signer, ["wss://relay.example", "wss://other.example"]).url
    parts = urlsplit(str(url).replace("bunker://", "http://"))  # what Stacker News does
    assert parts.hostname == signer.signer_key.pubkey
    assert parse_qs(parts.query) == {"relay": ["wss://relay.example", "wss://other.example"],
                                     "secret": [signer.secret]}


class FakePool:
    def __init__(self):
        self.published: list[Event] = []

    async def publish(self, event):
        self.published.append(event)
        return [PublishResult("fake", True)]


@pytest.mark.parametrize("cipher_class", [Nip04Cipher, Nip44Cipher])
def test_bunker_answers_in_the_request_scheme(signer, cipher_class):
    client = Identity.generate()
    connected = []
    bunker = Bunker(signer, ["wss://fake"], on_connect=lambda c, url: connected.append(c))
    pool = FakePool()
    to_signer = cipher_class.between(client, signer.signer_key.pubkey)
    request = json.dumps({"id": "r1", "method": "connect", "params": ["", signer.secret]})
    envelope = Event(kind=KIND_NOSTR_CONNECT, content=to_signer.encrypt(request),
                     tags=[["p", signer.signer_key.pubkey]]).sign(client)

    async def handle():
        await bunker._handle(pool, "wss://fake", envelope.to_dict())
        await asyncio.gather(*bunker._replies)

    asyncio.run(handle())

    [reply] = pool.published
    assert reply.verify() and reply.pubkey == signer.signer_key.pubkey
    assert reply.tags == [["p", client.pubkey]]
    assert Nip04Cipher.matches(reply.content) == (cipher_class is Nip04Cipher)
    assert json.loads(to_signer.decrypt(reply.content)) == {"id": "r1", "result": "ack"}
    assert connected == [client.pubkey]


def test_bunker_drops_forged_envelopes(signer):
    client = Identity.generate()
    envelope = Event(kind=KIND_NOSTR_CONNECT, content="x", tags=[]).sign(client)
    envelope.content = "tampered"
    pool = FakePool()
    asyncio.run(Bunker(signer, [])._handle(pool, "wss://fake", envelope.to_dict()))
    assert pool.published == []
