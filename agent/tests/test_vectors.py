# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""The Rust test vectors (src/proto.rs), reproduced byte for byte."""
from primeapprove.protocol import (action_code, action_hash, base45_decode, base45_encode, glyphs, kid,
                                   pairing_code, public_bytes, signing_key, verify_reply, parse_reply, ProtocolError)
import hashlib
import pytest

DEMO_ACTION = b'{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}'
DEMO_HASH = "1594e5cc61b278e99dba75aad80d8b2dd41e135820630c1e12584dda3b95d9d8"
# compact_reply_test_vector in proto.rs: app key = seed [7; 32], demo agent, demo request, AT.
REPLY_VECTOR = "PA1:W50H00PE4XS8-.CFPDUOQ65F+%N1KSUHI911B:D891NZDPID5VRFZKBHEDAB%W1J9QPKTOSI$6F+8KX.AO5MEC3IQG$A9QIB%UN/R70-F*XC7+DC PAW7"
DEMO_AGENT_SEED = hashlib.sha256(b"prime-approve DEMO agent key - public, never use for real").digest()


def test_demo_vector():
    h = action_hash(DEMO_ACTION)
    assert h == DEMO_HASH
    assert action_code(h) == "1594 E5CC"
    assert glyphs(h) == [(1, 0), (2, 2), (0, 3), (1, 1), (5, 3), (2, 3), (5, 2), (2, 1)]
    assert glyphs(h.upper()) == glyphs(h)


def test_kid_matches_rust():
    assert kid(public_bytes(signing_key(DEMO_AGENT_SEED))) == "230b544bde5c1af0"


def test_reply_vector_from_rust():
    app_pk = public_bytes(signing_key(bytes([7]) * 32))
    assert app_pk.hex() == "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    rid, k = "00112233445566778899aabbccddeeff", "230b544bde5c1af0"
    r = verify_reply(REPLY_VECTOR, app_pk, rid, k, DEMO_HASH)
    assert r is not None and r.approved and r.reason is None and r.at == 1_800_000_000
    assert verify_reply(REPLY_VECTOR, app_pk, rid, k, "0" * 64) is None
    assert verify_reply(REPLY_VECTOR, public_bytes(signing_key(bytes([9]) * 32)), rid, k, DEMO_HASH) is None
    assert verify_reply(REPLY_VECTOR, app_pk, rid[:16] + "f" * 16, k, DEMO_HASH) is None


def test_reply_tamper_fails():
    app_pk = public_bytes(signing_key(bytes([7]) * 32))
    raw = base45_decode(REPLY_VECTOR[4:])
    for i in range(len(raw)):
        t = bytearray(raw); t[i] ^= 0x01
        assert verify_reply("PA1:" + base45_encode(bytes(t)), app_pk, "00112233445566778899aabbccddeeff", "230b544bde5c1af0", DEMO_HASH) is None


def test_base45_rfc9285():
    for raw, enc in [(b"AB", "BB8"), (b"Hello!!", "%69 VD92EX0"), (b"base-45", "UJCLQE7W581"), (b"ietf!", "QED8WEX0"), (b"", "")]:
        assert base45_encode(raw) == enc and base45_decode(enc) == raw
    for bad in ["GGW", "ab", "A"]:
        with pytest.raises(ProtocolError):
            base45_decode(bad)
    with pytest.raises(ProtocolError):
        parse_reply("PA1:hello")


def test_pairing_code_shape():
    c = pairing_code(public_bytes(signing_key(bytes([1]) * 32)), public_bytes(signing_key(bytes([7]) * 32)))
    assert len(c) == 29 and len(c.split(" ")) == 6
