#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Decode a Prime Approve reply QR from a photo (or screenshot) and verify it.

Agent-side reference for the compact reply (README, "Reply QR"). Needs zbarimg (apt install
zbar-tools / brew install zbar) or the pyzbar module, plus the `cryptography` module.

  tools/decode_reply.py photo.jpg --pubkey <Prime app key hex> --id <request id hex> \
      --kid <agent kid hex> --hash <action hash hex>
  tools/decode_reply.py photo.jpg            # decode and parse only, no signature check

Exit code 0 only when the reply verifies and is an APPROVE (or, with no --pubkey, when it decodes).
"""
import argparse, hashlib, shutil, struct, subprocess, sys

B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
PREFIX, DOMAIN, VERSION, LEN = "PA1:", b"primeapprove-reply-v1\n", 1, 78
REASONS = ["wrong_action", "not_now", "unrecognized"]


def b45decode(s):
    v = [B45.index(c) for c in s]
    if len(v) % 3 == 1:
        raise ValueError("bad base45 length")
    out = bytearray()
    for i in range(0, len(v), 3):
        c = v[i:i + 3]
        if len(c) == 3:
            n = c[0] + c[1] * 45 + c[2] * 2025
            if n > 0xFFFF: raise ValueError("bad base45")
            out += bytes([n >> 8, n & 0xFF])
        else:
            n = c[0] + c[1] * 45
            if n > 0xFF: raise ValueError("bad base45")
            out.append(n)
    return bytes(out)


def scan(path):
    """All QR texts zbar finds in the image."""
    if shutil.which("zbarimg"):
        r = subprocess.run(["zbarimg", "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", path], capture_output=True, text=True)
        return [l for l in r.stdout.splitlines() if l]
    from pyzbar.pyzbar import decode
    from PIL import Image
    return [d.data.decode() for d in decode(Image.open(path))]


def parse(text):
    if not text.startswith(PREFIX):
        raise ValueError("not a PA1: reply")
    b = b45decode(text[len(PREFIX):])
    if len(b) != LEN or b[0] != VERSION:
        raise ValueError(f"wrong length {len(b)} or version {b[0]}")
    d = b[1]
    if not 1 <= d <= 5:
        raise ValueError(f"unknown decision byte {d}")
    return {"version": b[0], "decision": d, "approved": d == 1, "reason": REASONS[d - 3] if d >= 3 else None,
            "id_prefix": b[2:10].hex(), "at": struct.unpack(">I", b[10:14])[0], "sig": b[14:]}


def verify(r, pubkey, rid, kid, h):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    rid, kid, h = bytes.fromhex(rid), bytes.fromhex(kid), bytes.fromhex(h)
    if (len(rid), len(kid), len(h)) != (16, 8, 32):
        raise ValueError("id must be 16 bytes, kid 8, hash 32 (hex)")
    if rid[:8].hex() != r["id_prefix"]:
        return False
    msg = DOMAIN + bytes([r["version"], r["decision"]]) + rid + kid + h + struct.pack(">I", r["at"])
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey)).verify(r["sig"], msg)
        return True
    except Exception:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("photo")
    ap.add_argument("--pubkey", help="the Prime app public key you pinned at pairing (64 hex)")
    ap.add_argument("--id", help="the request id you issued (32 hex)")
    ap.add_argument("--kid", help="your agent key id (16 hex)")
    ap.add_argument("--agent-pk", help="your agent public key (64 hex); used to compute --kid")
    ap.add_argument("--hash", help="SHA-256 of the action you are about to run (64 hex)")
    a = ap.parse_args()
    texts = [t for t in scan(a.photo) if t.startswith(PREFIX)]
    if not texts:
        print("no PA1: reply QR found"); return 2
    r = parse(texts[0])
    print(f"decoded {len(texts[0])} chars: decision={'approve' if r['approved'] else 'deny'}"
          f"{' (' + r['reason'] + ')' if r['reason'] else ''} id_prefix={r['id_prefix']} at={r['at']}")
    if not a.pubkey:
        print("not verified (no --pubkey)"); return 0
    kid = a.kid or (a.agent_pk and hashlib.sha256(bytes.fromhex(a.agent_pk)).digest()[:8].hex())
    if not (a.id and kid and a.hash):
        print("need --id, --kid (or --agent-pk) and --hash to verify"); return 2
    ok = verify(r, a.pubkey, a.id, kid, a.hash)
    print("signature and request match: " + ("YES" if ok else "NO"))
    if ok and not r["approved"]:
        print("valid DENY: do not act")
    return 0 if ok and r["approved"] else 1


if __name__ == "__main__":
    sys.exit(main())
