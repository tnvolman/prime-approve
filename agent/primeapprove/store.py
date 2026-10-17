# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Files under ~/.primeapprove (or $PRIMEAPPROVE_HOME):

  agent.key          32-byte Ed25519 seed, hex, mode 600. Never printed.
  prime.json         the PINNED Prime app key, written only after the person confirms the pairing code
  pending/<id>.json  requests waiting for a reply
  pending/<id>.used  created (O_EXCL) when a reply for <id> is accepted: single use
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .protocol import ProtocolError, RequestRecord, public_bytes, signing_key


def home() -> Path:
    return Path(os.environ.get("PRIMEAPPROVE_HOME") or Path.home() / ".primeapprove")


def _private_dir(p: Path) -> Path:
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1)
    os.replace(tmp, path)


def create_key() -> bytes:
    """Creates agent.key (refuses to overwrite one). Returns the PUBLIC key."""
    path = _private_dir(home()) / "agent.key"
    seed = os.urandom(32)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise ProtocolError(f"{path} already exists; not overwriting it") from None
    with os.fdopen(fd, "w") as f:
        f.write(seed.hex() + "\n")
    os.chmod(path, 0o600)
    return public_bytes(signing_key(seed))


def load_key():
    path = home() / "agent.key"
    if not path.exists():
        raise ProtocolError("no agent key yet: run `pa init`")
    if path.stat().st_mode & 0o077:
        raise ProtocolError(f"{path} is readable by other users; run chmod 600 on it")
    return signing_key(bytes.fromhex(path.read_text().strip()))


def pin_prime(app_pk: bytes, code: str) -> Path:
    path = _private_dir(home()) / "prime.json"
    _write_json(path, {"app_pk": app_pk.hex(), "pairing_code": code, "pinned_at": int(time.time())})
    return path


def pinned_prime() -> bytes:
    path = home() / "prime.json"
    if not path.exists():
        raise ProtocolError("no Prime pinned yet: run `pa pair` and `pa pair-accept`")
    return bytes.fromhex(json.loads(path.read_text())["app_pk"])


def _pending_dir() -> Path:
    return _private_dir(home() / "pending")


def save_pending(r: RequestRecord) -> Path:
    path = _pending_dir() / f"{r.id}.json"
    _write_json(path, {"id": r.id, "kid": r.kid, "hash": r.hash, "exp": r.exp, "title": r.title,
                       "action": r.action, "created": int(time.time())})
    return path


def find_pending(id_prefix: str) -> dict | None:
    for p in sorted(_pending_dir().glob(f"{id_prefix}*.json")):
        d = json.loads(p.read_text())
        if d["id"][:16] == id_prefix:
            return d
    return None


def consume(req_id: str, outcome: str) -> bool:
    """Marks a request answered. False if it already was (a replayed reply)."""
    try:
        fd = os.open(_pending_dir() / f"{req_id}.used", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as f:
        f.write(f"{outcome} {int(time.time())}\n")
    return True
