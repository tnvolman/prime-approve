#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Thin wrapper around the agent library in agent/ (package `primeapprove`).

  tools/decode_reply.py PHOTO
      same as `pa verify PHOTO`: uses your pinned Prime key and pending requests.
  tools/decode_reply.py PHOTO --pubkey HEX --id HEX --kid HEX --hash HEX
      checks one reply against explicit values (handy for webcam tests); exit 0 only for a valid approve.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from primeapprove import cli, qr  # noqa: E402
from primeapprove.protocol import REPLY_PREFIX, parse_reply, verify_reply  # noqa: E402

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("photo")
for k in ("pubkey", "id", "kid", "hash"):
    ap.add_argument("--" + k)
a = ap.parse_args()
if not a.pubkey:
    sys.exit(cli.main(["verify", a.photo]))
text = qr.read_input(a.photo, REPLY_PREFIX)
r = parse_reply(text)
print(f"decoded {len(text)} chars: id_prefix={r.id_prefix} at={r.at}")
ok = verify_reply(text, bytes.fromhex(a.pubkey), a.id, a.kid, a.hash)
print("INVALID" if ok is None else "APPROVED" if ok.approved else f"DENIED({ok.reason})" if ok.reason else "DENIED")
sys.exit(0 if ok and ok.approved else 1 if ok else 2)
