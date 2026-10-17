# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Showing QR codes (qrcode) and reading them from photos (pyzbar, or the zbarimg command)."""
from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys

from .protocol import ProtocolError


def show(text: str, png: str | None = None, out=None) -> None:
    """Prints the QR as terminal blocks and, with `png`, saves it as an image. Low error correction:
    fewer, larger modules for the Prime's camera; the signature already catches a bad read."""
    import qrcode
    q = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=2)
    q.add_data(text)
    q.make(fit=True)
    buf = io.StringIO()
    q.print_ascii(out=buf, invert=True)
    (out or sys.stdout).write(buf.getvalue())
    if png:
        q.make_image(fill_color="black", back_color="white").save(png)


def scan(path: str) -> list[str]:
    """All QR texts found in an image file."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
        return [d.data.decode("ascii", "replace") for d in decode(Image.open(path))]
    except ImportError:
        pass
    if not shutil.which("zbarimg"):
        raise ProtocolError("reading photos needs pyzbar (pip install 'primeapprove[photo]') or zbarimg")
    r = subprocess.run(["zbarimg", "--quiet", "--raw", "-Sdisable", "-Sqrcode.enable", path], capture_output=True, text=True)
    return [line for line in r.stdout.splitlines() if line]


def read_input(arg: str, prefix: str) -> str:
    """The code text from an argument: a photo/screenshot path, `-` for stdin, or the text itself."""
    if arg == "-":
        arg = sys.stdin.readline().rstrip("\r\n")
    elif os.path.isfile(arg):
        found = [t for t in scan(arg) if t.startswith(prefix)]
        if not found:
            raise ProtocolError(f"no {prefix} code found in {arg}")
        return found[0]
    return arg.strip("\r\n")
