#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
# Report-only security scan. Exit 0 CLEAN, 1 FINDINGS, 2 SCAN INCOMPLETE.
# Does not change code, git history, or git settings.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
args=()
if [[ " ${*} " != *" --root "* && " ${*} " != *" --root="* ]]; then
  args+=(--root "$ROOT")
fi
exec python3 "$ROOT/scripts/security_scan.py" "${args[@]}" "$@"
