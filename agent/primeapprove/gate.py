# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""The GitHub gate: turns a Prime approval into something GitHub enforces.

Run it where the agent can't reach (another machine, another OS account, or a CI job the agent can't
edit), with its own state directory (default ~/.primeapprove-gate/, or $PRIMEAPPROVE_GATE_HOME) and its own
GitHub token. It trusts only what it pinned itself (`pa gate-trust`): the Prime's key and the agent keys.

For a reply it:
  1. reads the signed request (same strict parser as the Prime: exact fields, no repeats) and hashes the
     exact action bytes it carries; the action is never rebuilt from fields,
  2. refuses anything but a known tool (github.merge_pull_request), even when approved,
  3. verifies the reply against its pinned Prime key over the request id, agent kid and that hash,
     and checks expiry,
  4. fetches the PR and requires the same repo, number, open state, head SHA and base branch as the action
     (a PR retargeted to another base after approval is refused),
  5. marks the request used in its own store (single use), then
  6. --mode status: posts commit status `prime-approve/<base>` (e.g. `prime-approve/main`; success on
     approve, failure on deny) on that SHA, so a check required on main is only met by an approval for main;
     --mode merge: re-fetches the PR and re-checks base and head right before
     PUT /pulls/{n}/merge with sha=<approved head>, so GitHub itself refuses (409) if the head moved.
     GitHub's merge call can't check the base, so a retarget in the moment between the re-check and the
     merge is not caught. A deny merges nothing.
Exit codes: 0 done (approved and carried out), 1 denied, 2 refused or error. The token is never printed.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .protocol import ProtocolError, action_code, decode_request, fingerprint, verify_reply

DEFAULT_API = "https://api.github.com"
CONTEXT = "prime-approve"


def context_for(base: str) -> str:
    """Status context, one per base branch: `prime-approve/main`. Require this exact context on that branch."""
    return f"{CONTEXT}/{base}"


def gate_home() -> Path:
    return Path(os.environ.get("PRIMEAPPROVE_GATE_HOME") or Path.home() / ".primeapprove-gate")


def _private(p: Path) -> Path:
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


def trust(prime_pk: bytes, agent_pks: list[bytes], home: Path | None = None) -> Path:
    """Pins the Prime key and the agent keys this gate accepts (public keys only)."""
    if len(prime_pk) != 32 or not agent_pks or any(len(k) != 32 for k in agent_pks):
        raise ProtocolError("keys are 32 bytes (64 hex chars)")
    path = _private(home or gate_home()) / "gate.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"prime_pk": prime_pk.hex(), "agents": [k.hex() for k in agent_pks],
                               "pinned_at": int(time.time())}, indent=1) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    return path


def load_trust(home: Path) -> tuple[bytes, list[bytes]]:
    path = home / "gate.json"
    if not path.exists():
        raise ProtocolError(f"gate has no pinned keys yet: run `pa gate-trust` (state dir {home})")
    d = json.loads(path.read_text())
    return bytes.fromhex(d["prime_pk"]), [bytes.fromhex(k) for k in d["agents"]]


def load_token(token_file: str | None, home: Path, from_env: bool = False) -> str:
    """The gate's own token: --token-file, else <gate home>/token. $GITHUB_TOKEN only
    when asked (from_env), so a shared machine never hands the gate the agent's token. Never printed."""
    if from_env:
        tok = os.environ.get("GITHUB_TOKEN", "").strip()
        if not tok:
            raise ProtocolError("--token-from-env given but GITHUB_TOKEN is not set")
    else:
        path = Path(token_file) if token_file else home / "token"
        if not path.exists():
            raise ProtocolError(f"no GitHub token: put the gate's own token in {path} or use --token-file "
                                "(GITHUB_TOKEN is ignored unless you pass --token-from-env)")
        tok = path.read_text().strip()
    if not tok or any(c.isspace() for c in tok):
        raise ProtocolError("GitHub token is empty or malformed")
    return tok


class GitHub:
    def __init__(self, token: str, api: str = DEFAULT_API):
        self._token, self.api = token, api.rstrip("/")

    def call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(self.api + path, method=method,
                                     data=None if body is None else json.dumps(body).encode())
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "prime-approve-gate")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                code, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, raw = e.code, e.read()
        except urllib.error.URLError as e:
            raise ProtocolError(f"can't reach GitHub API: {e.reason}") from None
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {}
        return code, data if isinstance(data, dict) else {"items": data}


@dataclass
class Result:
    code: int        # 0 done, 1 denied, 2 refused
    message: str
    posted: dict | None = None


def _used(home: Path, req_id: str) -> Path:
    return _private(home / "used") / f"{req_id}.used"


def run_gate(request_qr: str, reply_qr: str, gh: GitHub, *, mode: str = "status", home: Path | None = None,
             now: int | None = None, test_skip_head_precheck: bool = False) -> Result:
    home = home or gate_home()
    now = int(time.time()) if now is None else now
    if mode not in ("status", "merge"):
        return Result(2, f"REFUSED (unknown mode {mode!r})")
    if test_skip_head_precheck and mode != "merge":
        return Result(2, "REFUSED (the head pre-check can only be skipped in merge mode, where GitHub checks the sha)")
    prime_pk, agents = load_trust(home)
    try:
        body, view, _ = decode_request(request_qr, agents)
    except ProtocolError as e:
        return Result(2, f"REFUSED (request: {e})")
    if view.verb is None or not view.fields:
        return Result(2, f"REFUSED (tool {view.tool!r} is not a known action; the gate only carries out known tools)")
    a = view.fields
    h = hashlib.sha256(body["action"].encode("ascii")).hexdigest()   # the exact bytes the Prime hashed
    code = action_code(h)
    reply = verify_reply(reply_qr, prime_pk, body["id"], body["kid"], h)
    if reply is None:
        return Result(2, "REFUSED (reply doesn't verify against the gate's pinned Prime key for this request)")
    if now > body["exp"]:
        return Result(2, "REFUSED (request expired)")
    used = _used(home, body["id"]).exists()
    repo, pr, head, base = a["repo"], a["pr"], a["head"], a["base"]
    status, p = gh.call("GET", f"/repos/{repo}/pulls/{pr}")
    if status != 200:
        return Result(2, f"REFUSED (GitHub returned {status} for {repo} PR #{pr}; nothing posted)")
    got_repo = (p.get("base") or {}).get("repo", {}).get("full_name", "")
    got_head = (p.get("head") or {}).get("sha", "")
    got_base = (p.get("base") or {}).get("ref", "")
    if got_repo.lower() != repo.lower() or p.get("number") != pr:
        return Result(2, f"REFUSED (wrong repo or PR: GitHub says {got_repo} #{p.get('number')}, action says {repo} #{pr}; nothing posted)")
    if p.get("state") != "open" or p.get("merged"):
        return Result(2, f"REFUSED ({repo} PR #{pr} is not open; nothing posted)")
    if got_head != head and not test_skip_head_precheck:
        note = " This reply was also already used." if used else ""
        return Result(2, f"REFUSED (head moved: PR head is {got_head[:12]}, approved head is {head[:12]}; nothing posted).{note}")
    if got_base != base:
        note = " This reply was also already used." if used else ""
        return Result(2, f"REFUSED (base moved: PR now targets {got_base!r}, approved base is {base!r}; nothing posted).{note}")
    if used or not _consume(home, body["id"], "approved" if reply.approved else "denied"):
        return Result(2, "REFUSED (this request was already answered; replies are single-use)")
    if mode == "merge":
        if not reply.approved:
            return Result(1, f"DENIED{f'({reply.reason})' if reply.reason else ''} on Prime: nothing merged")
        # Last look right before merging: GitHub's merge call takes the head sha but not the base,
        # so the base is checked here (a retarget after this call and before the merge isn't caught).
        st, p2 = gh.call("GET", f"/repos/{repo}/pulls/{pr}")
        b2 = (p2.get("base") or {}).get("ref", "")
        if st != 200 or b2 != base:
            return Result(2, f"REFUSED (base moved right before the merge: PR now targets {b2!r}, approved base is {base!r}; nothing merged)")
        st, m = gh.call("PUT", f"/repos/{repo}/pulls/{pr}/merge", {"sha": head, "merge_method": a["method"]})
        if st == 200 and m.get("merged"):
            return Result(0, f"MERGED {repo} PR #{pr} into {base} at {head[:12]} ({a['method']}), code {code}", m)
        return Result(2, f"REFUSED by GitHub ({st}: {m.get('message', 'no message')}); nothing merged", {"status": st, **m})
    state = "success" if reply.approved else "failure"
    desc = f"Approved on Prime · code {code}" if reply.approved else \
        f"Denied on Prime{f' ({reply.reason})' if reply.reason else ''} · code {code}"
    ctx = context_for(base)
    st, s = gh.call("POST", f"/repos/{repo}/statuses/{head}", {"state": state, "context": ctx, "description": desc})
    if st != 201:
        return Result(2, f"ERROR (GitHub returned {st} posting the status: {s.get('message', '')})")
    return Result(0 if reply.approved else 1, f"POSTED {ctx}={state} on {repo}@{head} ({desc})", s)


def _consume(home: Path, req_id: str, outcome: str) -> bool:
    try:
        fd = os.open(_used(home, req_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as f:
        f.write(f"{outcome} {int(time.time())}\n")
    return True


def describe_trust(home: Path) -> str:
    prime_pk, agents = load_trust(home)
    return f"Prime {fingerprint(prime_pk)}; agents " + ", ".join(fingerprint(k) for k in agents)
