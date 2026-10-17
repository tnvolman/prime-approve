# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""`pa`: the agent side of Prime Approve.

  pa init                         create the agent key (~/.primeapprove/agent.key, mode 600)
  pa pair [--png FILE]            show a pairing offer for the Prime to scan (valid 10 minutes)
  pa pair-accept CODE|PHOTO       check the Prime's answer, compare codes, pin the Prime's key on "y"
  pa request --action JSON ...    show a signed request and its action code; remember it as pending
  pa verify CODE|PHOTO            check the Prime's reply; exit 0 only for a valid, unused APPROVE
  pa gate-trust --prime-key HEX --agent-key HEX   pin keys in the gate's own state dir
  pa gate REQUEST REPLY [--mode status|merge]      the GitHub gate (run it where the agent can't reach)

CODE|PHOTO is the code text, `-` to read it from stdin, or a photo/screenshot of the QR.
Exit codes: 0 ok / approved, 1 denied or declined, 2 invalid or error.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import gate, qr, store
from .protocol import (MAX_LIFETIME_SECS, PAIRED_PREFIX, REPLY_PREFIX, REQ_PREFIX, ProtocolError, action_code, summary_line,
                       build_request, encode_pair_offer, fingerprint, glyphs, kid, pairing_code, parse_reply,
                       public_bytes, verify_paired_reply, verify_reply, GLYPH_COLORS, GLYPH_SHAPES)


def cmd_init(a) -> int:
    pk = store.create_key()
    print(f"Created {store.home() / 'agent.key'} (mode 600). The private key is never printed.")
    print(f"Agent key {fingerprint(pk)}  kid {kid(pk)}")
    print("Next: pa pair")
    return 0


def cmd_pair(a) -> int:
    sk = store.load_key()
    offer = encode_pair_offer(sk, int(time.time()) + MAX_LIFETIME_SECS)
    qr.show(offer, a.png)
    print(f"Pairing offer for agent key {fingerprint(public_bytes(sk))}, valid 10 minutes.")
    if a.png:
        print(f"Saved {a.png}")
    if a.text:
        print(offer)
    print("Scan it on the Prime with Scan code, name the agent and tap Pair. Then: pa pair-accept <answer photo or text>")
    return 0


def cmd_pair_accept(a) -> int:
    sk = store.load_key()
    pk = public_bytes(sk)
    app_pk = verify_paired_reply(qr.read_input(a.answer, PAIRED_PREFIX), pk)
    code = pairing_code(pk, app_pk)
    print(f"The Prime's answer is validly signed. Prime key {fingerprint(app_pk)}")
    print(f"\n    PAIRING CODE  {code}\n")
    try:
        old = store.pinned_prime()
    except ProtocolError:
        old = None
    if old is not None and old != app_pk:
        # Replacing the trusted Prime is what an attacker would want; make it deliberate.
        print("WARNING: This replaces the Prime you trust.")
        print(f"    pinned now  {fingerprint(old)}")
        print(f"    new Prime   {fingerprint(app_pk)}")
        sys.stdout.write("If the Prime shows the same code and you mean to switch, type 'replace': ")
        sys.stdout.flush()
        ok = sys.stdin.readline().strip() == "replace"
    else:
        sys.stdout.write("Does the Prime show the same code? [y/N] ")
        sys.stdout.flush()
        ok = sys.stdin.readline().strip().lower() in ("y", "yes")
    if not ok:
        print("Not pinned" + (" (the Prime you trust is unchanged)" if old else "") + ". Tap Don't match on the Prime too, so it saves nothing either.")
        return 1
    path = store.pin_prime(app_pk, code)
    print(f"Pinned the Prime's key in {path}. Now tap Codes match on the Prime.")
    return 0


def _action_bytes(a) -> bytes:
    if a.action_file:
        with open(a.action_file, "rb") as f:
            return f.read()
    return a.action.encode()


def cmd_request(a) -> int:
    sk = store.load_key()
    try:
        store.pinned_prime()
    except ProtocolError as e:
        print(f"warning: {e}. You won't be able to verify the reply.", file=sys.stderr)
    r = build_request(sk, _action_bytes(a), a.title, a.details.replace("\\n", "\n"), agent=a.agent,
                      ttl=a.ttl, now=int(time.time()))
    store.save_pending(r)
    qr.show(r.qr, a.png)
    if a.png:
        print(f"Saved {a.png}")
    if a.text:
        print(r.qr)
    shapes = ", ".join(f"{GLYPH_COLORS[c]} {GLYPH_SHAPES[s]}" for c, s in glyphs(r.hash))
    print(f"Request {r.id}  ({len(r.qr)} bytes, expires in {a.ttl // 60}:{a.ttl % 60:02d})")
    if r.view and r.view.verb:
        print(f"\nThe Prime will show:  {summary_line(r.view)}  ({r.view.detail}), high impact")
    else:
        print(f"\nThe Prime doesn't know tool {r.view.tool!r}: it will show the raw action, marked high impact.")
    print(f"\n    ACTION CODE  {action_code(r.hash)}\n    {shapes}\n")
    print("Check the Prime shows this same code. Then: pa verify <reply photo or text>")
    return 0


def cmd_verify(a) -> int:
    text = qr.read_input(a.reply, REPLY_PREFIX)
    try:
        r = parse_reply(text)
    except ProtocolError as e:
        print(f"INVALID ({e})"); return 2
    app_pk = store.pinned_prime()
    sk = store.load_key()
    rec = store.find_pending(r.id_prefix)
    if rec is None:
        print("INVALID (no pending request with this id)"); return 2
    if rec["kid"] != kid(public_bytes(sk)):
        print("INVALID (pending request was made with a different agent key)"); return 2
    ok = verify_reply(text, app_pk, rec["id"], rec["kid"], rec["hash"])
    if ok is None:
        print("INVALID (signature doesn't verify against the pinned Prime key for this request)"); return 2
    if int(time.time()) > rec["exp"]:
        print("INVALID (request expired; ask again)"); return 2
    outcome = "approved" if ok.approved else f"denied:{ok.reason or ''}"
    if not store.consume(rec["id"], outcome):
        print("INVALID (this request was already answered; replies are single-use)"); return 2
    if ok.approved:
        print(f"APPROVED  {action_code(rec['hash'])}  {rec['title']}")
        print(f"action: {rec['action']}")
        return 0
    print(f"DENIED({ok.reason})" if ok.reason else "DENIED")
    return 1


def _code_arg(arg: str, prefix: str) -> str:
    """Code text, `-`, a text file holding the code, or a photo."""
    if arg != "-" and os.path.isfile(arg):
        try:
            t = Path(arg).read_text().strip()
            if t.startswith(prefix):
                return t
        except (UnicodeDecodeError, ValueError):
            pass
    return qr.read_input(arg, prefix)


def _gate_home(a) -> Path:
    return Path(a.gate_home) if a.gate_home else gate.gate_home()


def cmd_gate_trust(a) -> int:
    try:
        prime = bytes.fromhex(a.prime_key)
        agents = [bytes.fromhex(k) for k in a.agent_key]
    except ValueError:
        raise ProtocolError("keys must be hex") from None
    path = gate.trust(prime, agents, _gate_home(a))
    print(f"Pinned in {path}: {gate.describe_trust(_gate_home(a))}")
    return 0


def cmd_gate(a) -> int:
    home = _gate_home(a)
    req = _code_arg(a.request, REQ_PREFIX)
    reply = _code_arg(a.reply, REPLY_PREFIX)
    gh = gate.GitHub(gate.load_token(a.token_file, home), a.api or os.environ.get("PRIMEAPPROVE_GITHUB_API") or gate.DEFAULT_API)
    if a.test_skip_head_precheck:
        print("TEST ONLY: skipping the gate's head pre-check (merge mode; GitHub still checks the sha)")
    r = gate.run_gate(req, reply, gh, mode=a.mode, home=home, test_skip_head_precheck=a.test_skip_head_precheck)
    print(r.message)
    return r.code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pa", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the agent key")
    s = sub.add_parser("pair", help="show a pairing offer QR")
    s.add_argument("--png"); s.add_argument("--text", action="store_true", help="also print the code text")
    s = sub.add_parser("pair-accept", help="check the Prime's answer and pin its key")
    s.add_argument("answer")
    s = sub.add_parser("request", help="show a signed request QR")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--action", help="the exact action JSON; its exact bytes are hashed")
    g.add_argument("--action-file", help="read the exact action bytes from a file")
    s.add_argument("--title", default="", help="your description; the Prime shows it only as 'Agent says'")
    s.add_argument("--details", default="", help="up to 280 chars; \\n for a new line")
    s.add_argument("--agent", default="agent", help="display name inside the request (the Prime shows its own name)")
    s.add_argument("--ttl", type=int, default=MAX_LIFETIME_SECS, help="seconds until expiry, at most 600")
    s.add_argument("--png"); s.add_argument("--text", action="store_true", help="also print the code text")
    s = sub.add_parser("verify", help="check the Prime's reply")
    s.add_argument("reply")
    s = sub.add_parser("gate-trust", help="pin the Prime key and agent keys for the gate")
    s.add_argument("--prime-key", required=True, help="the Prime's app public key, 64 hex")
    s.add_argument("--agent-key", required=True, action="append", help="an agent public key, 64 hex (repeatable)")
    s.add_argument("--gate-home", help="gate state dir (default $PRIMEAPPROVE_GATE_HOME or ~/.primeapprove-gate)")
    s = sub.add_parser("gate", help="verify a reply and mark (or merge) the exact PR head on GitHub")
    s.add_argument("request", help="the signed request: code text, a text file, `-` or a photo")
    s.add_argument("reply", help="the Prime's reply: code text, a text file, `-` or a photo")
    s.add_argument("--mode", choices=["status", "merge"], default="status")
    s.add_argument("--api", help=f"GitHub API base URL (default $PRIMEAPPROVE_GITHUB_API or {gate.DEFAULT_API})")
    s.add_argument("--token-file", help="file holding the GitHub token (default: $GITHUB_TOKEN, else <gate home>/token)")
    s.add_argument("--gate-home", help="gate state dir (default $PRIMEAPPROVE_GATE_HOME or ~/.primeapprove-gate)")
    s.add_argument("--test-skip-head-precheck", action="store_true", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        return {"init": cmd_init, "pair": cmd_pair, "pair-accept": cmd_pair_accept,
                "request": cmd_request, "verify": cmd_verify, "gate-trust": cmd_gate_trust, "gate": cmd_gate}[a.cmd](a)
    except ProtocolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
