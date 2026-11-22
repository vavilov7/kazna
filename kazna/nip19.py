"""Bech32 encodings for Nostr entities (NIP-19): npub, nsec and nevent."""

from collections.abc import Iterable

import bech32

NEVENT_SPECIAL = 0
NEVENT_RELAY = 1
NEVENT_AUTHOR = 2
NEVENT_KIND = 3


def encode(hrp: str, data: bytes) -> str:
    return bech32.bech32_encode(hrp, bech32.convertbits(data, 8, 5))


def decode(expected_hrp: str, value: str) -> bytes:
    hrp, words = bech32.bech32_decode(value.strip().lower())
    if words is None or hrp != expected_hrp:
        raise ValueError(f"not a valid {expected_hrp} string")
    data = bech32.convertbits(words, 5, 8, False)
    if data is None:
        raise ValueError(f"not a valid {expected_hrp} string")
    return bytes(data)


def encode_nevent(event_id: str, relays: Iterable[str] = (), author: str | None = None,
                  kind: int | None = None) -> str:
    tlv = _tlv(NEVENT_SPECIAL, bytes.fromhex(event_id))
    for relay in relays:
        tlv += _tlv(NEVENT_RELAY, relay.encode())
    if author:
        tlv += _tlv(NEVENT_AUTHOR, bytes.fromhex(author))
    if kind is not None:
        tlv += _tlv(NEVENT_KIND, kind.to_bytes(4, "big"))
    return encode("nevent", tlv)


def _tlv(type_: int, value: bytes) -> bytes:
    return bytes([type_, len(value)]) + value
