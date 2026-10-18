# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""The Rust test vectors (src/proto.rs), reproduced byte for byte."""
from primeapprove.protocol import (action_code, action_hash, base45_decode, base45_encode, glyphs, kid,
                                   pairing_code, public_bytes, signing_key, verify_reply, parse_reply, ProtocolError)
import hashlib
import pytest

DEMO_ACTION = b'{"tool":"github.merge_pull_request","repo":"tnvolman/typewright-website-audit","pr":2,"base":"main","method":"squash","head":"33393c61b3e595bfb83bb9b909e280b2f40f0976"}'
DEMO_HASH = "f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d"
# compact_reply_test_vector in proto.rs: app key = seed [7; 32], demo agent, demo request, AT.
REPLY_VECTOR = "PA1:W50H00PE4XS8-.CFPDUOQEHIDYT2BN5 FYCK3H043P$PR9VC.CVR851BUOKMF P-$F0J0FFB1WVDOMVACB.EN29N2FM 1KTTH0DBBIF7T8DK*MIQV9O4V"
DEMO_AGENT_SEED = hashlib.sha256(b"prime-approve DEMO agent key - public, never use for real").digest()


def test_demo_vector():
    h = action_hash(DEMO_ACTION)
    assert h == DEMO_HASH
    assert action_code(h) == "F961 B2D1"
    assert glyphs(h) == [(3, 2), (7, 3), (6, 2), (7, 2), (2, 1), (7, 3), (2, 1), (5, 3)]
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
    a, p = public_bytes(signing_key(bytes([1]) * 32)), public_bytes(signing_key(bytes([7]) * 32))
    c = pairing_code(a, p, bytes([0x42]) * 16)
    assert len(c) == 29 and len(c.split(" ")) == 6
    # Same vector as pairing_code_mixes_the_primes_nonce in proto.rs.
    assert c.replace(" ", "") == hashlib.sha256(b"prime-approve pair v2" + a + p + bytes([0x42]) * 16).digest()[:12].hex().upper()
    assert pairing_code(a, p, bytes([0x43]) * 16) != c
    with pytest.raises(ProtocolError):
        pairing_code(a, p, b"short")


def test_paired_answer_must_be_v2_with_a_nonce():
    """Item 17: same refusals as paired_answer_must_be_v2_with_a_well_formed_nonce in proto.rs."""
    import json
    from primeapprove.protocol import PAIRED_DOMAIN, PAIRED_PREFIX, b64e, verify_paired_reply
    agent = public_bytes(signing_key(bytes([1]) * 32))
    app = signing_key(bytes([7]) * 32)
    pk, k = public_bytes(app).hex(), kid(agent)

    def sign(body, prefix=PAIRED_PREFIX, domain=PAIRED_DOMAIN):
        raw = json.dumps(body, separators=(",", ":")).encode()
        return f"{prefix}{b64e(raw)}.{b64e(app.sign(domain + raw))}"
    with pytest.raises(ProtocolError):
        verify_paired_reply(sign({"kid": k, "app_pk": pk}, "primeapprove:paired:v1:", b"primeapprove-paired-v1\n"), agent)
    for body in ({"kid": k, "app_pk": pk}, {"kid": k, "app_pk": pk, "nonce": "4242"},
                 {"kid": k, "app_pk": pk, "nonce": "AB" * 16}, {"kid": k, "app_pk": pk, "nonce": "42" * 16, "x": 1}):
        with pytest.raises(ProtocolError):
            verify_paired_reply(sign(body), agent)
    assert verify_paired_reply(sign({"kid": k, "app_pk": pk, "nonce": "42" * 16}), agent) == (public_bytes(app), bytes([0x42]) * 16)
