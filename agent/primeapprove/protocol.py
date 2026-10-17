# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prime Approve wire formats, mirroring src/proto.rs byte for byte.

Pure functions only: no files, no terminal. See cli.py and store.py for those.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__all__ = [
    "REQ_PREFIX", "PAIR_PREFIX", "PAIRED_PREFIX", "REPLY_PREFIX", "VERBS", "HIGH_IMPACT_VERBS", "DENY_REASONS",
    "MAX_QR", "MAX_LIFETIME_SECS", "ProtocolError", "Reply", "RequestRecord",
    "public_bytes", "signing_key", "kid", "action_hash", "action_code", "glyphs", "fingerprint", "pairing_code",
    "b64e", "b64d", "base45_encode", "base45_decode", "build_request", "encode_pair_offer", "verify_paired_reply",
    "parse_reply", "verify_reply", "is_elevated",
]

REQ_PREFIX = "primeapprove:v1:"
PAIR_PREFIX = "primeapprove:pair:v1:"
PAIRED_PREFIX = "primeapprove:paired:v1:"
REPLY_PREFIX = "PA1:"
REQ_DOMAIN = b"primeapprove-req-v1\n"
PAIR_DOMAIN = b"primeapprove-pair-v1\n"
PAIRED_DOMAIN = b"primeapprove-paired-v1\n"
PAIR_CODE_DOMAIN = b"prime-approve pair v1"
REPLY_DOMAIN = b"primeapprove-reply-v1\n"
REPLY_VERSION = 1
REPLY_LEN = 78
MAX_QR = 800
MAX_TITLE = 60
MAX_DETAILS = 280
MAX_OBJECT = 24
MAX_TARGET = 40
MAX_LIFETIME_SECS = 600
VERBS = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Run", "Grant", "Change"]
HIGH_IMPACT_VERBS = ["Merge", "Deploy", "Publish", "Delete", "Send", "Pay", "Sign", "Grant"]
DENY_REASONS = ["wrong_action", "not_now", "unrecognized"]
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


class ProtocolError(ValueError):
    """The input can't be used: the message says why. Nothing was signed or trusted."""


# ------------------------------------------------------------------ keys, hashes, codes

def signing_key(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ProtocolError("an Ed25519 seed is 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_bytes(key) -> bytes:
    pk = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw)


def kid(pk: bytes) -> str:
    """Key id: first 8 bytes of SHA-256(public key), 16 hex chars."""
    return hashlib.sha256(pk).digest()[:8].hex()


def action_hash(action: bytes) -> str:
    """SHA-256 of the EXACT action bytes the agent will run. No re-serialization or canonicalization:
    whatever bytes you hash are the bytes you must execute."""
    return hashlib.sha256(action).hexdigest()


def action_code(hash_hex: str) -> str:
    h = hash_hex[:8].upper()
    return f"{h[:4]} {h[4:]}"


GLYPH_COLORS = ["vermillion", "orange", "yellow", "bluish green", "sky blue", "blue", "reddish purple", "white"]
GLYPH_SHAPES = ["circle", "square", "ring", "outlined square"]


def glyphs(hash_hex: str) -> list[tuple[int, int]]:
    """(color id, shape id) for bytes 4..12 of the hash, as on the Prime's Review screen."""
    b = bytes.fromhex(hash_hex)
    return [(x & 7, (x >> 3) & 3) for x in b[4:12]]


def fingerprint(pk: bytes) -> str:
    d = hashlib.sha256(pk).digest()
    return f"{d[:4].hex()}…{d[28:].hex()}"


def pairing_code(agent_pk: bytes, app_pk: bytes) -> str:
    """First 12 bytes of SHA-256("prime-approve pair v1" || agent_pk || app_pk), 6 groups of 4 hex."""
    h = hashlib.sha256(PAIR_CODE_DOMAIN + agent_pk + app_pk).digest()[:12].hex().upper()
    return " ".join(h[i:i + 4] for i in range(0, 24, 4))


# ------------------------------------------------------------------ encodings

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    if not all(c.isalnum() or c in "-_" for c in s):
        raise ProtocolError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def base45_encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 2):
        c = data[i:i + 2]
        n, k = (c[0] * 256 + c[1], 3) if len(c) == 2 else (c[0], 2)
        for _ in range(k):
            out.append(B45[n % 45]); n //= 45
    return "".join(out)


def base45_decode(s: str) -> bytes:
    try:
        v = [B45.index(c) for c in s]
    except ValueError:
        raise ProtocolError("not base45") from None
    if len(v) % 3 == 1:
        raise ProtocolError("bad base45 length")
    out = bytearray()
    for i in range(0, len(v), 3):
        c = v[i:i + 3]
        if len(c) == 3:
            n = c[0] + c[1] * 45 + c[2] * 2025
            if n > 0xFFFF:
                raise ProtocolError("bad base45")
            out += bytes([n >> 8, n & 0xFF])
        else:
            n = c[0] + c[1] * 45
            if n > 0xFF:
                raise ProtocolError("bad base45")
            out.append(n)
    return bytes(out)


def _verify(pk: bytes, sig: bytes, msg: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def _split_signed(qr: str, prefix: str) -> tuple[bytes, bytes]:
    if len(qr) > MAX_QR:
        raise ProtocolError(f"{len(qr)} bytes is over the {MAX_QR}-byte cap")
    if not qr.startswith(prefix):
        raise ProtocolError("wrong prefix")
    body, dot, sig = qr[len(prefix):].partition(".")
    if not dot:
        raise ProtocolError("missing signature")
    body, sig = b64d(body), b64d(sig)
    if len(sig) != 64:
        raise ProtocolError("bad signature length")
    return body, sig


# ------------------------------------------------------------------ requests

def _printable(s: str, newline: bool) -> bool:
    return all(" " <= c <= "~" or (newline and c == "\n") for c in s)


def _summary_ok(s: str, limit: int) -> bool:
    return (0 < len(s) <= limit and s.strip() == s
            and all(c.isascii() and (c.isalnum() or c in " #._/:@-") for c in s))


def is_elevated(risk: str, verb: str | None) -> bool:
    return risk == "elevated" or verb in HIGH_IMPACT_VERBS


@dataclass
class RequestRecord:
    """What the agent keeps until the reply comes back."""
    id: str
    kid: str
    hash: str
    exp: int
    title: str
    action: str
    qr: str

    @property
    def code(self) -> str:
        return action_code(self.hash)


def build_request(sk: Ed25519PrivateKey, action: bytes, title: str, details: str = "", *, agent: str = "agent",
                  verb: str | None = None, object: str | None = None, target: str | None = None,
                  risk: str | None = None, ttl: int = MAX_LIFETIME_SECS, now: int, req_id: bytes | None = None
                  ) -> RequestRecord:
    """Builds and signs a request the Prime accepts. Checks everything the Prime checks, so a request
    that would be rejected fails here instead. `risk` defaults to elevated for high-impact verbs."""
    try:
        json.loads(action)
    except ValueError:
        raise ProtocolError("--action must be JSON") from None
    if not 0 < ttl <= MAX_LIFETIME_SECS:
        raise ProtocolError(f"expiry must be 1 to {MAX_LIFETIME_SECS} seconds out")
    if len(title) > MAX_TITLE or len(details) > MAX_DETAILS:
        raise ProtocolError(f"title is limited to {MAX_TITLE} chars and details to {MAX_DETAILS}")
    if not title or not _printable(title, False) or not _printable(details, True) or not _printable(agent, False):
        raise ProtocolError("title, details and agent name must be printable ASCII (newlines allowed in details)")
    parts = (verb, object, target)
    if any(p is not None for p in parts):
        if None in parts:
            raise ProtocolError("verb, object and target go together")
        if verb not in VERBS:
            raise ProtocolError(f"verb must be one of {', '.join(VERBS)}")
        if not _summary_ok(object, MAX_OBJECT) or not _summary_ok(target, MAX_TARGET):
            raise ProtocolError("object (24) and target (40): letters, digits, space and # . _ / : @ - only")
    risk = risk or ("elevated" if verb in HIGH_IMPACT_VERBS else "routine")
    if risk not in ("routine", "elevated"):
        raise ProtocolError("risk must be routine or elevated")
    if verb in HIGH_IMPACT_VERBS and risk != "elevated":
        raise ProtocolError(f"{verb} is always high impact; it can't be sent as routine")
    req_id = req_id if req_id is not None else os.urandom(16)
    if len(req_id) != 16:
        raise ProtocolError("request id is 16 bytes")
    pk = public_bytes(sk)
    h = action_hash(action)
    # Same field order as the Rust struct; serde_json produces the identical compact JSON.
    body = {"id": req_id.hex(), "kid": kid(pk), "agent": agent, "title": title, "details": details,
            "risk": risk, "hash": h, "exp": now + ttl}
    if verb is not None:
        body.update(verb=verb, object=object, target=target)
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=True).encode()
    qr = f"{REQ_PREFIX}{b64e(raw)}.{b64e(sk.sign(REQ_DOMAIN + raw))}"
    if len(qr) > MAX_QR:
        raise ProtocolError(f"request is {len(qr)} bytes; the Prime's cap is {MAX_QR}. Shorten the title or details")
    return RequestRecord(req_id.hex(), kid(pk), h, now + ttl, title, action.decode(), qr)


# ------------------------------------------------------------------ pairing

def encode_pair_offer(sk: Ed25519PrivateKey, exp: int) -> str:
    raw = json.dumps({"pk": public_bytes(sk).hex(), "exp": exp}, separators=(",", ":")).encode()
    return f"{PAIR_PREFIX}{b64e(raw)}.{b64e(sk.sign(PAIR_DOMAIN + raw))}"


def verify_paired_reply(qr: str, agent_pk: bytes) -> bytes:
    """Checks the Prime's pairing answer; returns the Prime's app key. Do NOT pin it until the person
    confirms `pairing_code(agent_pk, app_pk)` matches the code on the Prime."""
    body, sig = _split_signed(qr, PAIRED_PREFIX)
    try:
        r = json.loads(body)
        app_pk = bytes.fromhex(r["app_pk"])
        their_kid = r["kid"]
    except (ValueError, KeyError, TypeError):
        raise ProtocolError("bad pairing answer") from None
    if len(app_pk) != 32 or not _verify(app_pk, sig, PAIRED_DOMAIN + body):
        raise ProtocolError("pairing answer signature doesn't verify")
    if their_kid != kid(agent_pk):
        raise ProtocolError("this pairing answer is for a different agent key")
    return app_pk


# ------------------------------------------------------------------ replies

@dataclass
class Reply:
    version: int
    decision: int
    id_prefix: str
    at: int
    sig: bytes

    @property
    def approved(self) -> bool:
        return self.decision == 1

    @property
    def reason(self) -> str | None:
        return DENY_REASONS[self.decision - 3] if self.decision >= 3 else None


def parse_reply(qr: str) -> Reply:
    """Unpacks a PA1 reply WITHOUT verifying it. Use only to find the pending request (by id prefix)."""
    if not qr.startswith(REPLY_PREFIX):
        raise ProtocolError("not a PA1: reply")
    b = base45_decode(qr[len(REPLY_PREFIX):])
    if len(b) != REPLY_LEN or b[0] != REPLY_VERSION:
        raise ProtocolError("wrong reply length or version")
    if not 1 <= b[1] <= 5:
        raise ProtocolError("unknown decision")
    return Reply(b[0], b[1], b[2:10].hex(), struct.unpack(">I", b[10:14])[0], b[14:])


def verify_reply(qr: str, app_pk: bytes, req_id: str, req_kid: str, req_hash: str) -> Reply | None:
    """The agent-side check, same as `decode_reply` in proto.rs: the reply must be signed by the PINNED
    Prime key over the full id, this agent's kid and the full hash of the action about to run.
    Returns the reply (approve or deny) if it verifies, else None. Act only if `.approved`."""
    try:
        r = parse_reply(qr)
        rid, k, h = bytes.fromhex(req_id), bytes.fromhex(req_kid), bytes.fromhex(req_hash)
    except (ProtocolError, ValueError):
        return None
    if (len(rid), len(k), len(h)) != (16, 8, 32) or rid[:8].hex() != r.id_prefix:
        return None
    msg = REPLY_DOMAIN + bytes([r.version, r.decision]) + rid + k + h + struct.pack(">I", r.at)
    return r if _verify(app_pk, r.sig, msg) else None
