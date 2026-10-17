# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""The `pa` CLI, end to end against a stand-in Prime (Rust fixtures, or a test signer below)."""
import io
import json
import os
import stat
import struct
import sys

import pytest

from make_fixtures import FIXTURES, TEST_AGENT_SEED
from primeapprove import cli, store
from primeapprove.protocol import (REPLY_DOMAIN, base45_encode, kid, public_bytes, signing_key, RequestRecord)

RUST = json.loads((FIXTURES / "rust_to_py.json").read_text())
PY = json.loads((FIXTURES / "py_to_rust.json").read_text())
TEST_APP = signing_key(bytes([7]) * 32)  # same public TEST key the Rust fixtures use


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIMEAPPROVE_HOME", str(tmp_path / "pa"))
    return tmp_path / "pa"


def run(capsys, monkeypatch, *argv, stdin=""):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out + out.err


def use_test_agent(home):
    home.mkdir(mode=0o700, exist_ok=True)
    p = home / "agent.key"
    p.write_text(TEST_AGENT_SEED.hex() + "\n")
    os.chmod(p, 0o600)


def prime_reply(rec, decision, at=1_800_000_000, app=TEST_APP):
    """Test stand-in for the Prime's encode_reply (the real one is Rust; see the fixtures)."""
    rid, h = bytes.fromhex(rec.id), bytes.fromhex(rec.hash)
    k = bytes.fromhex(kid(public_bytes(signing_key(TEST_AGENT_SEED))))
    sig = app.sign(REPLY_DOMAIN + bytes([1, decision]) + rid + k + h + struct.pack(">I", at))
    return "PA1:" + base45_encode(bytes([1, decision]) + rid[:8] + struct.pack(">I", at) + sig)


def test_init_creates_private_key_and_never_prints_it(home, capsys, monkeypatch):
    code, out = run(capsys, monkeypatch, "init")
    assert code == 0
    key = home / "agent.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert key.read_text().strip() not in out
    assert run(capsys, monkeypatch, "init")[0] == 2, "never overwrites a key"
    os.chmod(key, 0o644)
    assert "chmod 600" in run(capsys, monkeypatch, "pair")[1]


def test_pair_shows_offer(home, capsys, monkeypatch, tmp_path):
    use_test_agent(home)
    code, out = run(capsys, monkeypatch, "pair", "--text", "--png", str(tmp_path / "offer.png"))
    assert code == 0 and "primeapprove:pair:v1:" in out and (tmp_path / "offer.png").exists()
    assert "valid 10 minutes" in out


def test_pair_accept_pins_only_on_yes(home, capsys, monkeypatch):
    use_test_agent(home)
    for answer in ["", "n", "no", "maybe"]:
        code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin=answer + "\n")
        assert code == 1 and "Not pinned" in out and not (home / "prime.json").exists()
        assert RUST["pairing_code"] in out
    code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin="y\n")
    assert code == 0 and json.loads((home / "prime.json").read_text())["app_pk"] == RUST["app_pk"]


def test_pair_accept_rejects_other_agent(home, capsys, monkeypatch):
    run(capsys, monkeypatch, "init")  # a random key, not the one the answer is for
    code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin="y\n")
    assert code == 2 and "different agent" in out and not (home / "prime.json").exists()


def pin(home):
    store.pin_prime(public_bytes(TEST_APP), "test")


def test_verify_rust_reply_single_use(home, capsys, monkeypatch):
    use_test_agent(home); pin(home)
    import time
    store.save_pending(RequestRecord(PY["request_id"], kid(public_bytes(signing_key(TEST_AGENT_SEED))), PY["request_hash"],
                                     int(time.time()) + 600, "Merge PR #2 into main", PY["action"], PY["request"]))
    code, out = run(capsys, monkeypatch, "verify", RUST["reply_approve"])
    assert code == 0 and out.startswith("APPROVED  1594 E5CC") and PY["action"] in out
    code, out = run(capsys, monkeypatch, "verify", RUST["reply_approve"])
    assert code == 2 and "already answered" in out


def test_request_then_verify_photo(home, capsys, monkeypatch, tmp_path):
    use_test_agent(home); pin(home)
    code, out = run(capsys, monkeypatch, "request", "--action", PY["action"], "--title", "Merge PR #2 into main",
                    "--text")
    assert code == 0 and "ACTION CODE  1594 E5CC" in out
    assert "The Prime will show:  Merge → PR #2 → tnvolman/typewright-website-audit  (squash merge at 33393c6)" in out
    pending = list((home / "pending").glob("*.json"))
    assert len(pending) == 1
    rec = json.loads(pending[0].read_text())
    assert rec["exp"] - int(__import__("time").time()) <= 600
    body = json.loads(__import__("primeapprove.protocol", fromlist=["b64d"]).b64d(
        [l for l in out.splitlines() if l.startswith("primeapprove:v2:")][0][16:].split(".")[0]))
    assert list(body) == ["id", "kid", "agent", "title", "details", "action", "exp"]
    assert body["action"] == PY["action"], "the Prime gets the action bytes, not a hash"

    class R: pass
    r = R(); r.id, r.hash = rec["id"], rec["hash"]
    # Reply as a photo: render the QR, then decode it from the PNG.
    import qrcode
    png = tmp_path / "reply.png"
    qrcode.make(prime_reply(r, 4), error_correction=qrcode.constants.ERROR_CORRECT_M).save(png)
    code, out = run(capsys, monkeypatch, "verify", str(png))
    assert code == 1 and out.strip() == "DENIED(not_now)"
    # The same request id can't be answered twice, even with an approve.
    assert run(capsys, monkeypatch, "verify", prime_reply(r, 1))[0] == 2


def test_verify_rejects_wrong_key_and_unknown_request(home, capsys, monkeypatch):
    use_test_agent(home); pin(home)
    run(capsys, monkeypatch, "request", "--action", '{"tool":"ci.run"}', "--title", "Run it", "--ttl", "60")
    rec = json.loads(next((home / "pending").glob("*.json")).read_text())

    class R: pass
    r = R(); r.id, r.hash = rec["id"], rec["hash"]
    code, out = run(capsys, monkeypatch, "verify", prime_reply(r, 1, app=signing_key(bytes([9]) * 32)))
    assert code == 2 and "pinned Prime key" in out
    r.hash = "00" * 32
    assert run(capsys, monkeypatch, "verify", prime_reply(r, 1))[0] == 2, "reply for a different action"
    r.id = "ff" * 16
    code, out = run(capsys, monkeypatch, "verify", prime_reply(r, 1))
    assert code == 2 and "no pending request" in out
    assert run(capsys, monkeypatch, "verify", "PA1:garbage")[0] == 2
    r.id, r.hash = rec["id"], rec["hash"]
    assert run(capsys, monkeypatch, "verify", prime_reply(r, 1))[0] == 0, "the real reply still works"


def test_request_refuses_what_the_prime_would_reject(home, capsys, monkeypatch):
    use_test_agent(home)
    ok = '{"tool":"ci.run"}'
    bad = [
        ["--action", "not json", "--title", "t"],
        ["--action", "{}", "--title", "t"],
        ["--action", '{"tool":"github.merge_pull_request","repo":"a/b","pr":2}'],
        ["--action", "{\"tool\":\"x\",\"t\":\"caf\u00e9\"}"],
        ["--action", ok, "--ttl", "601"],
        ["--action", ok, "--title", "x" * 61],
        ["--action", ok, "--title", "Merge PR\u202e2"],
        ["--action", ok, "--details", "y" * 281],
    ]
    for args in bad:
        assert run(capsys, monkeypatch, "request", *args)[0] == 2, args
    assert not list((home / "pending").glob("*.json")) if (home / "pending").exists() else True


def test_pair_accept_replacing_a_pinned_prime_needs_replace(home, capsys, monkeypatch):
    use_test_agent(home)
    other = signing_key(bytes([8]) * 32)
    store.pin_prime(public_bytes(other), "old")
    pinned = lambda: json.loads((home / "prime.json").read_text())["app_pk"]
    for answer in ["y", "yes", "", "Replace", "replace it"]:
        code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin=answer + "\n")
        assert code == 1 and "This replaces the Prime you trust" in out, answer
        assert pinned() == public_bytes(other).hex(), "old Prime still pinned"
    from primeapprove.protocol import fingerprint
    assert fingerprint(public_bytes(other)) in out and fingerprint(bytes.fromhex(RUST["app_pk"])) in out
    code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin="replace\n")
    assert code == 0 and pinned() == RUST["app_pk"]


def test_pair_accept_same_prime_again_is_a_plain_yes(home, capsys, monkeypatch):
    use_test_agent(home)
    store.pin_prime(bytes.fromhex(RUST["app_pk"]), "same")
    code, out = run(capsys, monkeypatch, "pair-accept", RUST["paired_reply"], stdin="y\n")
    assert code == 0 and "replaces" not in out and "[y/N]" in out


def test_request_unknown_tool_warns(home, capsys, monkeypatch):
    use_test_agent(home)
    code, out = run(capsys, monkeypatch, "request", "--action", '{"tool":"github.delete_repo","repo":"a/b"}')
    assert code == 0 and "doesn't know tool 'github.delete_repo'" in out and "high impact" in out
