# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cross tests with the Rust host-tests crate (host-tests/src/lib.rs, module `interop`)."""
import json
from pathlib import Path

from make_fixtures import FIXTURES, TEST_AGENT_SEED, py_to_rust
from primeapprove.protocol import pairing_code, public_bytes, signing_key, verify_paired_reply, verify_reply

RUST = json.loads((FIXTURES / "rust_to_py.json").read_text())
PY = json.loads((FIXTURES / "py_to_rust.json").read_text())


def test_python_fixture_is_current():
    # Rust checks py_to_rust.json; it must be exactly what this library produces today.
    assert py_to_rust() == PY


def test_rust_replies_verify_in_python():
    app_pk = bytes.fromhex(RUST["app_pk"])
    args = (app_pk, PY["request_id"], _kid(), PY["request_hash"])
    ok = verify_reply(RUST["reply_approve"], *args)
    assert ok is not None and ok.approved and ok.at == 1_800_000_000
    no = verify_reply(RUST["reply_deny_wrong_action"], *args)
    assert no is not None and not no.approved and no.reason == "wrong_action"
    plain = verify_reply(RUST["reply_deny"], *args)
    assert plain is not None and not plain.approved and plain.reason is None
    # Wrong action hash or wrong pinned key: nothing verifies.
    assert verify_reply(RUST["reply_approve"], app_pk, PY["request_id"], _kid(), "1" * 64) is None
    assert verify_reply(RUST["reply_approve"], public_bytes(signing_key(bytes([9]) * 32)), *args[1:]) is None


def test_rust_paired_reply_and_pairing_code():
    agent_pk = public_bytes(signing_key(TEST_AGENT_SEED))
    app_pk, nonce = verify_paired_reply(RUST["paired_reply"], agent_pk)
    assert app_pk.hex() == RUST["app_pk"] and nonce.hex() == RUST["pair_nonce"]
    assert pairing_code(agent_pk, app_pk, nonce) == RUST["pairing_code"] == RUST["pairing_code_1_7"]
    # Item 17: the nonce is part of the code; Rust and Python agree on a different nonce too.
    assert pairing_code(agent_pk, app_pk, bytes([0x43]) * 16) == RUST["pairing_code_other_nonce"] != RUST["pairing_code"]


def _kid():
    from primeapprove.protocol import kid
    return kid(public_bytes(signing_key(TEST_AGENT_SEED)))
