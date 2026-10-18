# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""The GitHub gate against a local fake GitHub API (no network)."""
import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from make_fixtures import TEST_AGENT_SEED
from primeapprove import cli, gate
from primeapprove.protocol import (REPLY_DOMAIN, REQ_DOMAIN, REQ_PREFIX, base45_encode, b64e, build_request, kid,
                                   public_bytes, signing_key)

APP = signing_key(bytes([7]) * 32)
AGENT = signing_key(TEST_AGENT_SEED)
REPO, PR = "tnvolman/prime-approve", 5
HEAD = "a" * 40
NOW = 1_800_000_000
TOKEN = "ghp_TESTTOKEN_never_printed_123"


def merge_action(repo=REPO, pr=PR, head=HEAD, method="squash", base="main"):
    return json.dumps({"tool": "github.merge_pull_request", "repo": repo, "pr": pr, "base": base, "method": method, "head": head},
                      separators=(",", ":")).encode()


def reply_for(rec, decision, app=APP):
    rid, h = bytes.fromhex(rec.id), bytes.fromhex(rec.hash)
    k = bytes.fromhex(kid(public_bytes(AGENT)))
    sig = app.sign(REPLY_DOMAIN + bytes([1, decision]) + rid + k + h + struct.pack(">I", NOW))
    return "PA1:" + base45_encode(bytes([1, decision]) + rid[:8] + struct.pack(">I", NOW) + sig)


class FakeGitHub:
    """Enough of the GitHub REST API: GET a PR, POST a status, PUT a merge (409 unless sha == head)."""
    def __init__(self):
        self.prs = {(REPO, PR): {"number": PR, "state": "open", "merged": False, "head": {"sha": HEAD},
                                 "base": {"ref": "main", "repo": {"full_name": REPO}}}}
        self.calls, self.statuses, self.merges = [], [], []
        # Called on each PR GET, after the answer is taken (tests use it to retarget the PR between the gate's calls).
        self.after_get = None
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body):
                b = json.dumps(body).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}")

            def _route(self, method):
                fake.calls.append((method, self.path, self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"message": "Bad credentials"})
                parts = self.path.strip("/").split("/")
                if method == "GET" and len(parts) == 5 and parts[3] == "pulls":
                    pr = fake.prs.get((f"{parts[1]}/{parts[2]}", int(parts[4])))
                    if not pr:
                        return self._send(404, {"message": "Not Found"})
                    # Answer with the PR as it is now; any change after_get makes shows on the NEXT GET.
                    # (Applied before sending, so the next request can't overtake it.)
                    snapshot = json.loads(json.dumps(pr))
                    if fake.after_get:
                        fake.after_get(pr)
                    return self._send(200, snapshot)
                if method == "POST" and len(parts) == 5 and parts[3] == "statuses":
                    b = self._body(); b["sha"] = parts[4]; b["repo"] = f"{parts[1]}/{parts[2]}"
                    fake.statuses.append(b)
                    return self._send(201, {"state": b["state"], "context": b["context"], "description": b["description"]})
                if method == "PUT" and len(parts) == 6 and parts[5] == "merge":
                    b = self._body(); pr = fake.prs[(f"{parts[1]}/{parts[2]}", int(parts[4]))]
                    if b.get("sha") != pr["head"]["sha"]:
                        return self._send(409, {"message": "Head branch was modified. Review and try the merge again."})
                    pr["merged"] = True; fake.merges.append(b)
                    return self._send(200, {"merged": True, "sha": "m" * 40, "message": "Pull Request successfully merged"})
                return self._send(404, {"message": "Not Found"})

            def do_GET(self): self._route("GET")
            def do_POST(self): self._route("POST")
            def do_PUT(self): self._route("PUT")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def gh():
    f = FakeGitHub()
    yield f
    f.server.shutdown()


@pytest.fixture
def ghome(tmp_path):
    h = tmp_path / "gate"
    gate.trust(public_bytes(APP), [public_bytes(AGENT)], h)
    return h


def req(action=None, **kw):
    return build_request(AGENT, action or merge_action(), "Merge PR #5", agent="t", ttl=600, now=NOW, **kw)


def go(gh, ghome, rec, reply, mode="status", **kw):
    return gate.run_gate(rec.qr, reply, gate.GitHub(TOKEN, gh.url), mode=mode, home=ghome, now=NOW + 10, **kw)


def test_approve_posts_success_on_the_exact_sha(gh, ghome):
    rec = req()
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 0, r.message
    assert gh.statuses == [{"state": "success", "context": "prime-approve/main", "sha": HEAD, "repo": REPO,
                            "description": f"Approved on Prime · code {rec.code}"}]


def test_deny_posts_failure(gh, ghome):
    rec = req()
    r = go(gh, ghome, rec, reply_for(rec, 3))
    assert r.code == 1 and gh.statuses[0]["state"] == "failure" and gh.statuses[0]["sha"] == HEAD
    assert "wrong_action" in gh.statuses[0]["description"]


def test_moved_head_refuses_and_posts_nothing(gh, ghome):
    rec = req()
    gh.prs[(REPO, PR)]["head"]["sha"] = "b" * 40
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 2 and "head moved" in r.message and gh.statuses == []


def test_wrong_repo_refuses(gh, ghome):
    rec = req(merge_action(repo="evil/other-repo"))
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 2 and "404" in r.message and gh.statuses == []
    # GitHub answers for a different repo (e.g. a redirect): still refused.
    gh.prs[("evil/other-repo", PR)] = json.loads(json.dumps(gh.prs[(REPO, PR)]))
    rec = req(merge_action(repo="evil/other-repo"))
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 2 and "wrong repo" in r.message and gh.statuses == []


def test_reuse_refuses(gh, ghome):
    rec = req()
    assert go(gh, ghome, rec, reply_for(rec, 1)).code == 0
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 2 and "single-use" in r.message and len(gh.statuses) == 1


def test_unknown_tool_refuses_even_when_approved(gh, ghome):
    rec = req(b'{"tool":"github.delete_repo","repo":"tnvolman/prime-approve"}')
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 2 and "not a known action" in r.message and gh.calls == []


def test_reply_must_be_from_the_pinned_prime_and_this_action(gh, ghome):
    rec = req()
    assert go(gh, ghome, rec, reply_for(rec, 1, app=signing_key(bytes([9]) * 32))).code == 2
    other = req(merge_action(head="c" * 40))
    assert go(gh, ghome, rec, reply_for(other, 1)).code == 2, "reply for a different action"
    assert gh.calls == [] and gh.statuses == []


def test_expired_refuses(gh, ghome):
    rec = req()
    r = gate.run_gate(rec.qr, reply_for(rec, 1), gate.GitHub(TOKEN, gh.url), home=ghome, now=NOW + 601)
    assert r.code == 2 and "expired" in r.message and gh.calls == []


def _resign(body: bytes) -> str:
    return f"{REQ_PREFIX}{b64e(body)}.{b64e(AGENT.sign(REQ_DOMAIN + body))}"


def test_request_must_be_strict(gh, ghome):
    rec = req()
    body = json.loads(__import__("primeapprove.protocol", fromlist=["b64d"]).b64d(rec.qr[len(REQ_PREFIX):].split(".")[0]))
    # A repeated field, an extra field, or an untrusted signer: refused before anything is fetched.
    raw = json.dumps(body, separators=(",", ":"))
    dup = raw[:-1] + ',"action":' + json.dumps(merge_action(head="c" * 40).decode()) + "}"
    extra = raw[:-1] + ',"hash":"00"}'
    for qr in (_resign(dup.encode()), _resign(extra.encode())):
        r = gate.run_gate(qr, reply_for(rec, 1), gate.GitHub(TOKEN, gh.url), home=ghome, now=NOW + 10)
        assert r.code == 2 and "request" in r.message
    stranger = signing_key(bytes([5]) * 32)
    bad = f"{REQ_PREFIX}{b64e(raw.encode())}.{b64e(stranger.sign(REQ_DOMAIN + raw.encode()))}"
    assert "trusted agent" in gate.run_gate(bad, reply_for(rec, 1), gate.GitHub(TOKEN, gh.url), home=ghome, now=NOW + 10).message
    assert gh.calls == []


def test_merge_mode_merges_the_approved_sha(gh, ghome):
    rec = req()
    r = go(gh, ghome, rec, reply_for(rec, 1), mode="merge")
    assert r.code == 0 and gh.merges == [{"sha": HEAD, "merge_method": "squash"}] and gh.statuses == []


def test_merge_mode_deny_merges_nothing(gh, ghome):
    rec = req()
    assert go(gh, ghome, rec, reply_for(rec, 2), mode="merge").code == 1 and gh.merges == []


def test_merge_mode_moved_head_both_layers_refuse(gh, ghome):
    rec = req()
    gh.prs[(REPO, PR)]["head"]["sha"] = "b" * 40
    r = go(gh, ghome, rec, reply_for(rec, 1), mode="merge")
    assert r.code == 2 and "head moved" in r.message and gh.merges == []
    # Without the gate's own pre-check (test-only), GitHub refuses the stale sha with 409.
    r = go(gh, ghome, rec, reply_for(rec, 1), mode="merge", test_skip_head_precheck=True)
    assert r.code == 2 and "409" in r.message and gh.merges == [] and not gh.prs[(REPO, PR)]["merged"]
    assert go(gh, ghome, rec, reply_for(rec, 1), mode="status", test_skip_head_precheck=True).code == 2


def test_cli_gate_never_prints_the_token(gh, ghome, tmp_path, capsys, monkeypatch):
    rec = req()
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    rf = tmp_path / "request.txt"; rf.write_text(rec.qr + "\n")
    code = cli.main(["gate", str(rf), reply_for(rec, 1), "--api", gh.url, "--gate-home", str(ghome), "--token-from-env"])
    out = capsys.readouterr()
    assert code == 0 and "POSTED prime-approve/main=success" in out.out
    assert TOKEN not in out.out + out.err
    monkeypatch.delenv("GITHUB_TOKEN")
    tf = tmp_path / "tok"; tf.write_text(TOKEN)
    rec2 = req()
    code = cli.main(["gate", rec2.qr, reply_for(rec2, 1), "--api", gh.url, "--gate-home", str(ghome), "--token-file", str(tf)])
    out = capsys.readouterr()
    assert code == 0 and TOKEN not in out.out + out.err
    # A bad token: GitHub's 401 is reported, the token is not.
    tf.write_text("wrong")
    rec3 = req()
    assert cli.main(["gate", rec3.qr, reply_for(rec3, 1), "--api", gh.url, "--gate-home", str(ghome), "--token-file", str(tf)]) == 2
    assert "wrong" not in capsys.readouterr().out.replace("wrong repo", "")


def test_gate_state_is_separate_from_the_agent(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIMEAPPROVE_GATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert gate.gate_home() == tmp_path / ".primeapprove-gate"
    with pytest.raises(Exception, match="gate-trust"):
        gate.load_trust(tmp_path / "nowhere")


def test_gate_prefers_its_own_token_file_over_the_environment(tmp_path, monkeypatch):
    home = tmp_path / "gatehome"; home.mkdir()
    (home / "token").write_text("gate-own-token\n")
    monkeypatch.setenv("GITHUB_TOKEN", "agent-token")
    assert gate.load_token(None, home) == "gate-own-token"
    assert gate.load_token(None, home, from_env=True) == "agent-token"
    (home / "token").unlink()
    with pytest.raises(gate.ProtocolError, match="ignored unless"):
        gate.load_token(None, home)
    monkeypatch.delenv("GITHUB_TOKEN")
    with pytest.raises(gate.ProtocolError, match="not set"):
        gate.load_token(None, home, from_env=True)


# ---- Item 16: the base (target) branch is part of the approval ----

def test_status_context_names_the_base(gh, ghome):
    gh.prs[(REPO, PR)]["base"]["ref"] = "release/1.2"
    rec = req(merge_action(base="release/1.2"))
    r = go(gh, ghome, rec, reply_for(rec, 1))
    assert r.code == 0, r.message
    assert [s["context"] for s in gh.statuses] == ["prime-approve/release/1.2"]
    assert "prime-approve/release/1.2=success" in r.message
    # The same PR approved for main gets its own context; one never stands in for the other.
    gh.prs[(REPO, PR)]["base"]["ref"] = "main"
    rec = req(merge_action(base="main"))
    assert go(gh, ghome, rec, reply_for(rec, 1)).code == 0
    assert [s["context"] for s in gh.statuses] == ["prime-approve/release/1.2", "prime-approve/main"]
    assert gate.context_for("main") == "prime-approve/main"


def test_deny_status_is_per_base_too(gh, ghome):
    rec = req()
    assert go(gh, ghome, rec, reply_for(rec, 2)).code == 1
    assert gh.statuses[0]["context"] == "prime-approve/main" and gh.statuses[0]["state"] == "failure"


def test_merge_mode_rechecks_base_right_before_merging(gh, ghome):
    rec = req()
    calls = []

    def retarget_after_first_look(pr):
        calls.append(1)
        if len(calls) == 1:
            pr["base"]["ref"] = "release"
    gh.after_get = retarget_after_first_look
    r = go(gh, ghome, rec, reply_for(rec, 1), mode="merge")
    assert r.code == 2 and "base moved right before the merge" in r.message, r.message
    assert gh.merges == [] and not gh.prs[(REPO, PR)]["merged"] and len(calls) == 2


def test_merge_mode_merges_into_the_approved_base(gh, ghome):
    rec = req()
    r = go(gh, ghome, rec, reply_for(rec, 1), mode="merge")
    assert r.code == 0 and "into main" in r.message and len(gh.merges) == 1


# ---- Item 17: a simulator key says so on GitHub ----

def test_simulator_key_says_approved_in_simulator(gh, tmp_path):
    home = tmp_path / "simgate"
    gate.trust(public_bytes(APP), [public_bytes(AGENT)], home, simulator=True)
    assert gate.is_simulator(home) and "simulator" in gate.describe_trust(home)
    rec = req()
    assert go(gh, home, rec, reply_for(rec, 1)).code == 0
    rec2 = req()
    assert go(gh, home, rec2, reply_for(rec2, 3)).code == 1
    assert [s["description"] for s in gh.statuses] == [f"Approved in simulator · code {rec.code}",
                                                      f"Denied in simulator (wrong_action) · code {rec2.code}"]


def test_default_trust_is_not_simulator(gh, ghome, tmp_path):
    assert not gate.is_simulator(ghome)
    rec = req()
    assert go(gh, ghome, rec, reply_for(rec, 1)).code == 0
    assert gh.statuses[0]["description"] == f"Approved on Prime · code {rec.code}"
    # A trust file from before the flag existed counts as not simulator.
    old = tmp_path / "old"; old.mkdir()
    (old / "gate.json").write_text(json.dumps({"prime_pk": "00" * 32, "agents": ["11" * 32], "pinned_at": 1}))
    assert not gate.is_simulator(old)


def test_cli_gate_trust_simulator_flag(tmp_path, capsys):
    home = tmp_path / "g"
    args = ["gate-trust", "--prime-key", public_bytes(APP).hex(), "--agent-key", public_bytes(AGENT).hex(), "--gate-home", str(home)]
    assert cli.main(args + ["--simulator"]) == 0 and "simulator" in capsys.readouterr().out
    assert json.loads((home / "gate.json").read_text())["simulator"] is True
    assert cli.main(args) == 0
    assert json.loads((home / "gate.json").read_text())["simulator"] is False
