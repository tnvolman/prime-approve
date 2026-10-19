#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Report-only security scan for Prime Approve.

Scans tracked text files and commits on local branches and tags for secrets,
and audits the Rust lockfiles and the Python dependencies in agent/. Prints a
report and does not change the tree, the history, or git settings. Without a
lockfile, pip-audit installs dependencies, and that install runs package code.

Exit codes:
  0  every check is CLEAN
  1  at least one check is FINDINGS, and none is SCAN INCOMPLETE
  2  any check is SCAN INCOMPLETE (tool missing, crashed, timed out, or
     output that could not be read). Findings from checks that finished
     are still listed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

CLEAN = "CLEAN"
FINDINGS = "FINDINGS"
INCOMPLETE = "SCAN INCOMPLETE"

# A forced tool path that is not an executable. Distinct from "not installed",
# but both mean that tool cannot be used.
_MISSING = object()


@dataclass
class Finding:
    rule: str
    file: str
    commit: str
    line: int
    fingerprint: str = ""
    package: str = ""
    version: str = ""
    aliases: str = ""
    kind: str = ""

    def render(self) -> str:
        if self.package:
            parts = [f"rule={self.rule}", f"file={self.file}", f"package={self.package}", f"version={self.version}"]
            if self.kind:
                parts.append(f"kind={self.kind}")
            if self.aliases:
                parts.append(f"aliases={self.aliases}")
            if self.line:
                parts.append(f"line={self.line}")
            return "  " + " ".join(parts)
        return (
            f"  rule={self.rule} file={self.file} commit={self.commit} "
            f"line={self.line} fingerprint={self.fingerprint}"
        )


@dataclass
class Check:
    name: str
    state: str
    tool: str
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""

    def render(self) -> str:
        lines = [f"{self.name}: {self.state} ({self.tool})"]
        if self.reason:
            lines.append(f"  reason={self.reason}")
        for item in self.findings:
            lines.append(item.render())
        return "\n".join(lines)


def fingerprint(secret: str) -> str:
    """Prefix of SHA-256 of the matched value. The value is not recoverable from this."""
    digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return "sha256:" + digest


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


# Specific rules. Patterns are written so this source file does not contain a
# full live-key shaped literal (GitHub push protection scans the committed text).
_BEGIN = "-----BEGIN "
_END = "-----END "
_PK_MARK = "PRIVATE KEY-----"

_SPECIFIC_RULES: list[tuple[str, re.Pattern[str], int, float]] = [
    ("github-pat", _compile(r"ghp_[0-9A-Za-z]{36}"), 0, 3.0),
    ("github-fine-grained-pat", _compile(r"github_pat_[0-9A-Za-z_]{82}"), 0, 3.0),
    ("github-oauth", _compile(r"gho_[0-9A-Za-z]{36}"), 0, 3.0),
    ("github-app-token", _compile(r"ghu_[0-9A-Za-z]{36}"), 0, 3.0),
    ("github-server-token", _compile(r"ghs_[0-9A-Za-z]{36}"), 0, 3.0),
    ("github-refresh-token", _compile(r"ghr_[0-9A-Za-z]{36}"), 0, 3.0),
    ("stripe-access-token", _compile(r"(?:sk|rk)_(?:live|test|prod)_[0-9A-Za-z]{10,99}"), 0, 2.0),
    (
        "aws-access-key",
        _compile(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}"),
        0,
        3.0,
    ),
    ("google-api-key", _compile(r"AIza[0-9A-Za-z\-_]{35}"), 0, 4.0),
]

_PRIVATE_KEY = _compile(
    re.escape(_BEGIN)
    + r"[A-Z0-9 ]{0,80}"
    + re.escape(_PK_MARK)
    + r"[\s\S]{40,}?"
    + re.escape(_END)
    + r"[A-Z0-9 ]{0,80}"
    + re.escape(_PK_MARK)
)

# Assignment-shaped values only. Pure hex (hashes, commit ids) stays under the
# entropy floor; the word "token" next to a short test placeholder does too.
_GENERIC = _compile(
    r"(?i)\b(?:api[ _-]?key|secret|token|password|passwd|credential|access[ _-]?key)\b"
    r"[^\n]{0,40}[=:][ \t]{0,5}['\"]?([A-Za-z0-9+/_.=-]{20,150})"
)
_GENERIC_ENTROPY = 4.5

_SECRET_SCRUBBERS = [rule[1] for rule in _SPECIFIC_RULES] + [_PRIVATE_KEY, _GENERIC]


def scrub(text: str) -> str:
    """Drop anything that looks like a secret before it can reach the report."""
    redacted = text
    for pattern in _SECRET_SCRUBBERS:
        redacted = pattern.sub("[redacted]", redacted)
    return redacted


def scan_text(text: str) -> list[tuple[str, int, str]]:
    """Return (rule, line, secret) hits in one file. Callers must not print secret."""
    hits: list[tuple[str, int, str]] = []
    covered: list[tuple[int, int]] = []

    def add(rule: str, start: int, end: int, secret: str) -> None:
        if not secret:
            return
        line = text.count("\n", 0, start) + 1
        hits.append((rule, line, secret))
        covered.append((start, end))

    for rule, pattern, group, minimum in _SPECIFIC_RULES:
        for match in pattern.finditer(text):
            secret = match.group(group)
            if shannon_entropy(secret) < minimum:
                continue
            add(rule, match.start(group), match.end(group), secret)

    for match in _PRIVATE_KEY.finditer(text):
        add("private-key", match.start(), match.end(), match.group(0))

    for match in _GENERIC.finditer(text):
        secret = match.group(1)
        span = (match.start(1), match.end(1))
        if any(not (span[1] <= start or span[0] >= end) for start, end in covered):
            continue
        if shannon_entropy(secret) < _GENERIC_ENTROPY:
            continue
        if re.fullmatch(r"[0-9a-fA-F]+", secret) and len(secret) in {32, 40, 64}:
            continue
        add("high-entropy", match.start(1), match.end(1), secret)
    return hits


def _which(name: str) -> Path | None:
    found = shutil.which(name)
    if found:
        return Path(found)
    candidate = Path.home() / ".local" / "bin" / name
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def resolve_tool(env_key: str, binary: str):
    """Path, _MISSING when a requested path is unusable, or None when unset and absent."""
    if env_key in os.environ:
        raw = os.environ[env_key].strip()
        path = Path(raw) if raw else None
        if path and path.is_file() and os.access(path, os.X_OK):
            return path
        return _MISSING
    return _which(binary)


def run_command(args: list[str], timeout: int, cwd: Path | None = None):
    """Run a tool. Returns (returncode, stdout, timed_out). stderr is discarded.

    stderr is discarded so a tool that echoes a match cannot leak it into the
    report. On timeout the whole process group is killed.
    """
    proc = subprocess.Popen(
        args,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        return None, b"", True
    return proc.returncode, stdout or b"", False


def parse_json_blob(blob: bytes):
    text = blob.decode("utf-8", "replace").strip()
    if not text:
        raise ValueError("empty output")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end <= start:
            start = text.find("[")
            end = text.rfind("]")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start : end + 1])


def git_output(root: Path, args: list[str], timeout: int) -> tuple[bytes | None, str]:
    code, stdout, timed_out = run_command(["git", "--no-pager", "-C", str(root), *args], timeout)
    if timed_out:
        return None, "git timed out"
    if code != 0:
        return None, f"git {' '.join(args)} failed"
    return stdout, ""


def tracked_files(root: Path, timeout: int) -> tuple[list[str] | None, str]:
    stdout, err = git_output(root, ["ls-files", "-z"], timeout)
    if stdout is None:
        return None, err or "could not list tracked files"
    files = [item.decode("utf-8", "replace") for item in stdout.split(b"\0") if item]
    return files, ""


def is_text_file(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf", ".otf"}:
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size > 20_000_000:
        return False
    try:
        with path.open("rb") as handle:
            sample = handle.read(4096)
    except OSError:
        return False
    return b"\0" not in sample


def _hits_to_findings(hits: list[tuple[str, int, str]], file: str, commit: str) -> list[Finding]:
    found: list[Finding] = []
    seen: set[tuple[str, str, str, int, str]] = set()
    for rule, line, secret in hits:
        item = Finding(
            rule=rule,
            file=file,
            commit=commit,
            line=line,
            fingerprint=fingerprint(secret),
        )
        key = (item.rule, item.file, item.commit, item.line, item.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        found.append(item)
    return found


def scan_worktree_builtin(root: Path, timeout: int) -> Check:
    files, err = tracked_files(root, timeout)
    if files is None:
        return Check("secrets-worktree", INCOMPLETE, "builtin", reason=err)
    findings: list[Finding] = []
    for rel in files:
        path = root / rel
        if not path.is_file() or not is_text_file(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return Check("secrets-worktree", INCOMPLETE, "builtin", reason=f"could not read {rel}")
        findings.extend(_hits_to_findings(scan_text(text), rel, "working-tree"))
    state = FINDINGS if findings else CLEAN
    return Check("secrets-worktree", state, "builtin", findings=_sort_secret_findings(findings))


def scan_history_builtin(root: Path, timeout: int) -> Check:
    stdout, err = git_output(root, ["rev-list", "--reverse", "--all"], timeout)
    if stdout is None:
        return Check("secrets-history", INCOMPLETE, "builtin", reason=err or "could not read git history")
    commits = [line.strip() for line in stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    findings: list[Finding] = []
    seen_blobs: set[tuple[str, str]] = set()
    for commit in commits:
        listing, list_err = git_output(root, ["ls-tree", "-r", "-z", commit], timeout)
        if listing is None:
            return Check("secrets-history", INCOMPLETE, "builtin", reason=list_err or "could not read a commit tree")
        # mode SP type SP hash TAB path NUL
        for entry in listing.split(b"\0"):
            if not entry or b"\t" not in entry:
                continue
            meta, path_b = entry.split(b"\t", 1)
            meta_parts = meta.split()
            if len(meta_parts) < 3 or meta_parts[1] != b"blob":
                continue
            blob = meta_parts[2].decode("ascii", "replace")
            rel = path_b.decode("utf-8", "replace")
            key = (rel, blob)
            if key in seen_blobs:
                continue
            seen_blobs.add(key)
            data, data_err = git_output(root, ["cat-file", "blob", blob], timeout)
            if data is None:
                return Check("secrets-history", INCOMPLETE, "builtin", reason=data_err or "could not read a blob")
            if b"\0" in data or len(data) > 20_000_000:
                continue
            suffix = Path(rel).suffix.lower()
            if suffix in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz"}:
                continue
            text = data.decode("utf-8", "replace")
            findings.extend(_hits_to_findings(scan_text(text), rel, commit))
    state = FINDINGS if findings else CLEAN
    return Check("secrets-history", state, "builtin", findings=_sort_secret_findings(findings))


def _sort_secret_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (item.file, item.line, item.rule, item.commit, item.fingerprint))


def _relative(root: Path, file_name: str) -> str:
    path = Path(file_name)
    if not path.is_absolute():
        path = root / path
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return file_name.replace("\\", "/")


def _gitleaks_findings(data, root: Path, commit_override: str | None) -> list[Finding]:
    if not isinstance(data, list):
        raise ValueError("gitleaks report was not a list")
    findings: list[Finding] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError("gitleaks report entry was not an object")
        secret = item.get("Secret") or item.get("Match") or ""
        if not isinstance(secret, str) or not secret:
            raise ValueError("gitleaks report entry had no secret field to fingerprint")
        rule = str(item.get("RuleID") or "gitleaks")
        file_name = _relative(root, str(item.get("File") or ""))
        if commit_override is not None:
            commit = commit_override
        else:
            commit = str(item.get("Commit") or "unknown")
        line = int(item.get("StartLine") or 0)
        findings.append(
            Finding(rule=rule, file=file_name, commit=commit, line=line, fingerprint=fingerprint(secret))
        )
    return _sort_secret_findings(findings)


def scan_gitleaks(root: Path, binary: Path, timeout: int, history: bool, tracked: set[str] | None) -> Check:
    name = "secrets-history" if history else "secrets-worktree"
    report_dir = Path(tempfile.mkdtemp(prefix="security-scan-"))
    report = report_dir / "gitleaks.json"
    try:
        command = [
            str(binary),
            "detect",
            "--source",
            str(root),
            "--no-banner",
            "--log-level",
            "error",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--exit-code",
            "1",
        ]
        if history:
            command.append("--log-opts=--all")
        else:
            command.append("--no-git")
        code, _stdout, timed_out = run_command(command, timeout, cwd=root)
        if timed_out:
            return Check(name, INCOMPLETE, "gitleaks", reason=f"timed out after {timeout}s")
        if code not in (0, 1):
            return Check(name, INCOMPLETE, "gitleaks", reason=f"gitleaks exited {code}")
        if not report.exists() or report.stat().st_size == 0:
            data = []
        else:
            try:
                data = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return Check(name, INCOMPLETE, "gitleaks", reason="gitleaks output was not valid JSON")
        try:
            findings = _gitleaks_findings(data, root, "working-tree" if not history else None)
        except (ValueError, TypeError) as exc:
            return Check(name, INCOMPLETE, "gitleaks", reason=scrub(str(exc))[:200])
        if not history and tracked is not None:
            findings = [item for item in findings if item.file in tracked and not item.file.startswith(".git")]
        if findings:
            return Check(name, FINDINGS, "gitleaks", findings=findings)
        if code == 0:
            return Check(name, CLEAN, "gitleaks")
        return Check(name, INCOMPLETE, "gitleaks", reason="gitleaks exited 1 with no readable findings")
    finally:
        shutil.rmtree(report_dir, ignore_errors=True)


def _trufflehog_rows(blob: bytes) -> list[dict]:
    text = blob.decode("utf-8", "replace").strip()
    if not text:
        return []
    rows: list[dict] = []
    if text.startswith("["):
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            raise ValueError("trufflehog output was not a list")
        for row in parsed:
            if not isinstance(row, dict):
                raise ValueError("trufflehog report entry was not an object")
            rows.append(row)
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if not isinstance(row, dict):
            raise ValueError("trufflehog report entry was not an object")
        rows.append(row)
    return rows


def _trufflehog_secret(row: dict) -> str:
    secret = row.get("Raw")
    if not isinstance(secret, str) or not secret:
        secret = row.get("RawV2")
    if not isinstance(secret, str) or not secret:
        raise ValueError("trufflehog report entry had no secret field to fingerprint")
    return secret


def _trufflehog_findings(blob: bytes, root: Path, commit_override: str | None) -> list[Finding]:
    rows = _trufflehog_rows(blob)
    findings: list[Finding] = []
    for row in rows:
        secret = _trufflehog_secret(row)
        meta = ((row.get("SourceMetadata") or {}).get("Data") or {}) if isinstance(row.get("SourceMetadata"), dict) else {}
        file_name = ""
        line_no = 0
        commit = commit_override or "unknown"
        git_meta = meta.get("Git") if isinstance(meta.get("Git"), dict) else None
        file_meta = meta.get("Filesystem") if isinstance(meta.get("Filesystem"), dict) else None
        source = git_meta or file_meta or {}
        file_name = _relative(root, str(source.get("file") or source.get("path") or ""))
        try:
            line_no = int(source.get("line") or 0)
        except (TypeError, ValueError):
            line_no = 0
        if commit_override is None and git_meta and git_meta.get("commit"):
            commit = str(git_meta.get("commit"))
        rule = str(row.get("DetectorName") or "trufflehog")
        findings.append(Finding(rule=rule, file=file_name, commit=commit, line=line_no, fingerprint=fingerprint(secret)))
    return _sort_secret_findings(findings)


def scan_trufflehog(root: Path, binary: Path, timeout: int, history: bool, tracked: set[str] | None) -> Check:
    name = "secrets-history" if history else "secrets-worktree"
    if history:
        command = [str(binary), "git", f"file://{root}", "--json", "--no-update", "--no-verification"]
    else:
        command = [str(binary), "filesystem", str(root), "--json", "--no-update", "--no-verification"]
    code, stdout, timed_out = run_command(command, timeout, cwd=root)
    if timed_out:
        return Check(name, INCOMPLETE, "trufflehog", reason=f"timed out after {timeout}s")
    if code is None:
        return Check(name, INCOMPLETE, "trufflehog", reason="trufflehog failed to start")
    try:
        findings = _trufflehog_findings(stdout, root, "working-tree" if not history else None)
    except json.JSONDecodeError:
        return Check(name, INCOMPLETE, "trufflehog", reason="trufflehog output was not valid JSON")
    except (ValueError, TypeError) as exc:
        return Check(name, INCOMPLETE, "trufflehog", reason=scrub(str(exc))[:200])
    if not history and tracked is not None:
        findings = [item for item in findings if item.file in tracked and ".git/" not in f"/{item.file}"]
    if findings:
        return Check(name, FINDINGS, "trufflehog", findings=findings)
    if code == 0:
        return Check(name, CLEAN, "trufflehog")
    return Check(name, INCOMPLETE, "trufflehog", reason=f"trufflehog exited {code} with no readable findings")


def scan_secrets(root: Path, timeout: int, mode: str) -> list[Check]:
    files, err = tracked_files(root, timeout)
    tracked = set(files) if files is not None else None
    if mode == "auto":
        gitleaks = resolve_tool("SECURITY_SCAN_GITLEAKS", "gitleaks")
        trufflehog = resolve_tool("SECURITY_SCAN_TRUFFLEHOG", "trufflehog")
        if isinstance(gitleaks, Path):
            mode = "gitleaks"
        elif isinstance(trufflehog, Path):
            mode = "trufflehog"
        else:
            mode = "builtin"
    if mode == "builtin":
        return [scan_worktree_builtin(root, timeout), scan_history_builtin(root, timeout)]
    if mode == "gitleaks":
        binary = resolve_tool("SECURITY_SCAN_GITLEAKS", "gitleaks")
        if not isinstance(binary, Path):
            reason = "gitleaks not found"
            return [
                Check("secrets-worktree", INCOMPLETE, "gitleaks", reason=reason),
                Check("secrets-history", INCOMPLETE, "gitleaks", reason=reason),
            ]
        if tracked is None:
            return [
                Check("secrets-worktree", INCOMPLETE, "gitleaks", reason=err or "could not list tracked files"),
                scan_gitleaks(root, binary, timeout, True, None),
            ]
        return [
            scan_gitleaks(root, binary, timeout, False, tracked),
            scan_gitleaks(root, binary, timeout, True, None),
        ]
    if mode == "trufflehog":
        binary = resolve_tool("SECURITY_SCAN_TRUFFLEHOG", "trufflehog")
        if not isinstance(binary, Path):
            reason = "trufflehog not found"
            return [
                Check("secrets-worktree", INCOMPLETE, "trufflehog", reason=reason),
                Check("secrets-history", INCOMPLETE, "trufflehog", reason=reason),
            ]
        return [
            scan_trufflehog(root, binary, timeout, False, tracked),
            scan_trufflehog(root, binary, timeout, True, tracked),
        ]
    return [Check("secrets-worktree", INCOMPLETE, mode, reason=f"unknown secret scanner {mode}")]


_RUST_WARNING_KINDS = ("unmaintained", "unsound", "yanked", "notice")


def _osv_kind(vuln: dict) -> str:
    """Kind shared with cargo audit: vulnerability, or an informational warning kind."""
    values = []
    specific = vuln.get("database_specific")
    if isinstance(specific, dict):
        values.append(specific.get("informational"))
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        nested = affected.get("database_specific")
        if isinstance(nested, dict):
            values.append(nested.get("informational"))
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        kind = value.strip().lower()
        if kind in _RUST_WARNING_KINDS:
            return kind
    return "vulnerability"


def _rust_finding(
    rule: str,
    lock_rel: str,
    lock_text: str,
    name: str,
    version: str,
    aliases: str,
    kind: str,
) -> Finding:
    return Finding(
        rule=rule,
        file=lock_rel,
        commit="working-tree",
        line=_lock_line(lock_text, name, version),
        package=name,
        version=version,
        aliases=aliases,
        kind=kind,
    )


def _lock_line(text: str, package: str, version: str) -> int:
    lines = text.splitlines()
    name_line = f'name = "{package}"'
    version_line = f'version = "{version}"'
    for index, line in enumerate(lines):
        if line.strip() != name_line:
            continue
        window = lines[index : index + 8]
        if any(item.strip() == version_line for item in window):
            return index + 1
    return 0


def _dep_findings_from_osv(data, lock_rel: str, lock_text: str) -> tuple[list[Finding], int]:
    if not isinstance(data, dict):
        raise ValueError("osv-scanner output was not an object")
    results = data.get("results") or []
    if not isinstance(results, list):
        raise ValueError("osv-scanner results were not a list")
    packages = 0
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for result in results:
        if not isinstance(result, dict):
            continue
        for pkg in result.get("packages") or []:
            if not isinstance(pkg, dict):
                continue
            packages += 1
            info = pkg.get("package") or {}
            name = str(info.get("name") or "")
            version = str(info.get("version") or "")
            for vuln in pkg.get("vulnerabilities") or []:
                if not isinstance(vuln, dict):
                    continue
                rule = str(vuln.get("id") or "osv")
                key = (rule, name, version)
                if key in seen:
                    continue
                seen.add(key)
                aliases = vuln.get("aliases") or []
                alias_text = ",".join(str(alias) for alias in aliases if alias and alias != rule)
                findings.append(
                    _rust_finding(rule, lock_rel, lock_text, name, version, alias_text, _osv_kind(vuln))
                )
    findings.sort(key=lambda item: (item.file, item.package, item.version, item.rule, item.kind))
    return findings, packages


def audit_with_osv(lock: Path, root: Path, binary: Path, timeout: int, name: str | None = None) -> Check:
    rel = str(lock.relative_to(root)) if lock.is_relative_to(root) else str(lock)
    if name is None:
        name = f"deps-rust:{rel}" if lock.name == "Cargo.lock" else "deps-python:agent"
    command = [
        str(binary),
        "scan",
        "source",
        "-L",
        str(lock),
        "-f",
        "json",
        "--verbosity",
        "error",
        "--all-packages",
    ]
    code, stdout, timed_out = run_command(command, timeout, cwd=root)
    tool = "osv-scanner"
    if timed_out:
        return Check(name, INCOMPLETE, tool, reason=f"timed out after {timeout}s")
    if code is None:
        return Check(name, INCOMPLETE, tool, reason="osv-scanner failed to start")
    try:
        data = parse_json_blob(stdout)
        text = lock.read_text(encoding="utf-8", errors="replace")
        findings, packages = _dep_findings_from_osv(data, rel, text)
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return Check(name, INCOMPLETE, tool, reason="osv-scanner output was not readable")
    if packages == 0:
        return Check(name, INCOMPLETE, tool, reason="lockfile produced no packages")
    if findings:
        return Check(name, FINDINGS, tool, findings=findings)
    if code == 0:
        return Check(name, CLEAN, tool)
    return Check(name, INCOMPLETE, tool, reason=f"osv-scanner exited {code} with no readable findings")


def _cargo_audit_command() -> list[str] | object | None:
    resolved = resolve_tool("SECURITY_SCAN_CARGO_AUDIT", "cargo-audit")
    if resolved is _MISSING:
        return _MISSING
    if isinstance(resolved, Path):
        return [str(resolved)]
    if "SECURITY_SCAN_CARGO_AUDIT" in os.environ:
        return _MISSING
    cargo = _which("cargo")
    if cargo is None:
        return None
    code, _stdout, timed_out = run_command([str(cargo), "audit", "--version"], timeout=30)
    if timed_out or code != 0:
        return None
    return [str(cargo), "audit"]


def _cargo_audit_entry(item: dict, kind: str, lock_rel: str, lock_text: str) -> Finding:
    if not isinstance(item, dict):
        raise ValueError("cargo audit report entry was not an object")
    advisory = item.get("advisory") or {}
    if advisory is None:
        advisory = {}
    if not isinstance(advisory, dict):
        raise ValueError("cargo audit advisory was not an object")
    package = item.get("package") or {}
    if not isinstance(package, dict):
        raise ValueError("cargo audit package was not an object")
    rule = str(advisory.get("id") or kind)
    name = str(package.get("name") or advisory.get("package") or "")
    version = str(package.get("version") or "")
    aliases = advisory.get("aliases") or []
    if not isinstance(aliases, list):
        aliases = []
    alias_text = ",".join(str(alias) for alias in aliases if alias and alias != rule)
    return _rust_finding(rule, lock_rel, lock_text, name, version, alias_text, kind)


def _dep_findings_from_cargo_audit(data, lock_rel: str, lock_text: str) -> list[Finding]:
    if not isinstance(data, dict):
        raise ValueError("cargo audit output was not an object")
    vulns = data.get("vulnerabilities") or {}
    if not isinstance(vulns, dict):
        raise ValueError("cargo audit vulnerabilities were not an object")
    items = vulns.get("list") or []
    if not isinstance(items, list):
        raise ValueError("cargo audit vulnerabilities were not a list")
    warnings = data.get("warnings") or {}
    if not isinstance(warnings, dict):
        raise ValueError("cargo audit warnings were not an object")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(item: dict, kind: str) -> None:
        finding = _cargo_audit_entry(item, kind, lock_rel, lock_text)
        key = (finding.rule, finding.package, finding.version, finding.kind)
        if key in seen:
            return
        seen.add(key)
        findings.append(finding)

    for item in items:
        add(item, "vulnerability")
    kinds = [kind for kind in _RUST_WARNING_KINDS if kind in warnings]
    kinds.extend(sorted(kind for kind in warnings if kind not in _RUST_WARNING_KINDS))
    for kind in kinds:
        entries = warnings[kind]
        if not isinstance(entries, list):
            raise ValueError("cargo audit warnings were not readable")
        for item in entries:
            add(item, str(kind))
    findings.sort(key=lambda item: (item.package, item.version, item.rule, item.kind))
    return findings


def audit_with_cargo(lock: Path, root: Path, command: list[str], timeout: int) -> Check:
    rel = str(lock.relative_to(root))
    name = f"deps-rust:{rel}"
    code, stdout, timed_out = run_command([*command, "--json", "--file", str(lock)], timeout, cwd=root)
    tool = "cargo-audit"
    if timed_out:
        return Check(name, INCOMPLETE, tool, reason=f"timed out after {timeout}s")
    if code is None:
        return Check(name, INCOMPLETE, tool, reason="cargo audit failed to start")
    try:
        data = parse_json_blob(stdout)
        text = lock.read_text(encoding="utf-8", errors="replace")
        findings = _dep_findings_from_cargo_audit(data, rel, text)
    except (OSError, ValueError, json.JSONDecodeError, TypeError):
        return Check(name, INCOMPLETE, tool, reason="cargo audit output was not readable")
    if findings:
        return Check(name, FINDINGS, tool, findings=findings)
    if code == 0:
        return Check(name, CLEAN, tool)
    return Check(name, INCOMPLETE, tool, reason=f"cargo audit exited {code} with no readable findings")


def rust_lockfiles(root: Path, timeout: int) -> tuple[list[Path] | None, str]:
    files, err = tracked_files(root, timeout)
    if files is None:
        return None, err
    locks = []
    for rel in files:
        if rel == "Cargo.lock" or rel.endswith("/Cargo.lock"):
            path = root / rel
            if path.is_file():
                locks.append(path)
    return locks, ""


def audit_rust(root: Path, timeout: int) -> list[Check]:
    locks, err = rust_lockfiles(root, timeout)
    if locks is None:
        return [Check("deps-rust", INCOMPLETE, "cargo-audit", reason=err or "could not list lockfiles")]
    if not locks:
        return []
    cargo = _cargo_audit_command()
    osv = resolve_tool("SECURITY_SCAN_OSV_SCANNER", "osv-scanner")
    checks: list[Check] = []
    for lock in locks:
        rel = str(lock.relative_to(root))
        name = f"deps-rust:{rel}"
        if isinstance(cargo, list):
            checks.append(audit_with_cargo(lock, root, cargo, timeout))
            continue
        if isinstance(osv, Path):
            checks.append(audit_with_osv(lock, root, osv, timeout))
            continue
        checks.append(Check(name, INCOMPLETE, "cargo-audit", reason="cargo-audit and osv-scanner not found"))
    return checks


_PINNED_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.\-]*(?:\[[^\]]+\])?\s*==\s*[A-Za-z0-9][A-Za-z0-9.*!+_=-]*$"
)


def _requirement_lines(path: Path) -> list[str]:
    lines = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        lines.append(line)
    return lines


def _all_pinned(path: Path) -> bool:
    lines = _requirement_lines(path)
    return bool(lines) and all(_PINNED_REQUIREMENT.match(line) for line in lines)


def _pyproject_dependency_lines(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"(?m)^dependencies\s*=\s*\[(.*?)\]", text, re.S)
    if not match:
        return []
    body = match.group(1).strip()
    if not body:
        return []
    return [item.strip().strip('"').strip("'") for item in body.split(",") if item.strip()]


def _dep_findings_from_pip_audit(data, file_rel: str) -> list[Finding]:
    if not isinstance(data, dict):
        raise ValueError("pip-audit output was not an object")
    deps = data.get("dependencies")
    if not isinstance(deps, list):
        raise ValueError("pip-audit output had no dependencies list")
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for dep in deps:
        if not isinstance(dep, dict):
            continue
        if dep.get("skip_reason"):
            raise ValueError("a dependency was skipped")
        name = str(dep.get("name") or "")
        version = str(dep.get("version") or "")
        for vuln in dep.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            rule = str(vuln.get("id") or "PYSEC")
            key = (rule, name, version)
            if key in seen:
                continue
            seen.add(key)
            aliases = vuln.get("aliases") or []
            alias_text = ",".join(str(alias) for alias in aliases if alias and alias != rule)
            findings.append(
                Finding(
                    rule=rule,
                    file=file_rel,
                    commit="working-tree",
                    line=0,
                    package=name,
                    version=version,
                    aliases=alias_text,
                )
            )
    findings.sort(key=lambda item: (item.package, item.version, item.rule))
    return findings


def audit_with_pip(target: Path, root: Path, binary: Path, timeout: int, project: bool, name: str = "deps-python:agent") -> Check:
    rel = str(target.relative_to(root))
    command = [str(binary), "-f", "json", "--progress-spinner", "off", "--desc", "off"]
    expects_packages = True
    if project:
        expects_packages = bool(_pyproject_dependency_lines(target))
        command.append(str(target.parent if target.name == "pyproject.toml" else target))
    else:
        lines = _requirement_lines(target)
        expects_packages = bool(lines)
        command.extend(["-r", str(target)])
        if lines and _all_pinned(target):
            # Pinned files can be audited without installing them. pip-audit
            # exits 1 when that audit finds vulnerabilities; that is findings.
            command.extend(["--no-deps", "--disable-pip"])
    code, stdout, timed_out = run_command(command, timeout, cwd=root)
    tool = "pip-audit"
    if timed_out:
        return Check(name, INCOMPLETE, tool, reason=f"timed out after {timeout}s")
    if code is None:
        return Check(name, INCOMPLETE, tool, reason="pip-audit failed to start")
    try:
        data = parse_json_blob(stdout)
        findings = _dep_findings_from_pip_audit(data, rel if not project else "agent/pyproject.toml")
        dep_count = len((data.get("dependencies") or [])) if isinstance(data, dict) else 0
    except (ValueError, json.JSONDecodeError, TypeError):
        return Check(name, INCOMPLETE, tool, reason="pip-audit output was not readable")
    if expects_packages and dep_count == 0 and not findings:
        return Check(name, INCOMPLETE, tool, reason="no dependencies were audited")
    if findings:
        # Exit code 1 from pip-audit means vulnerabilities were found.
        return Check(name, FINDINGS, tool, findings=findings)
    if code == 0:
        return Check(name, CLEAN, tool)
    return Check(name, INCOMPLETE, tool, reason=f"pip-audit exited {code} with no readable findings")


def python_targets(root: Path, timeout: int) -> tuple[list[tuple[str, Path]] | None, str]:
    files, err = tracked_files(root, timeout)
    if files is None:
        return None, err
    agent_files = [rel for rel in files if rel.startswith("agent/")]
    targets: list[tuple[str, Path]] = []
    for rel in agent_files:
        name = Path(rel).name
        path = root / rel
        if not path.is_file():
            continue
        if name.startswith("requirements") and name.endswith(".txt"):
            targets.append(("requirements", path))
        elif name in {"poetry.lock", "uv.lock", "Pipfile.lock", "pylock.toml"}:
            targets.append(("lock", path))
    if targets:
        return targets, ""
    pyproject = root / "agent" / "pyproject.toml"
    if "agent/pyproject.toml" in agent_files and pyproject.is_file():
        return [("pyproject", pyproject)], ""
    return [], ""


def audit_python(root: Path, timeout: int) -> list[Check]:
    targets, err = python_targets(root, timeout)
    if targets is None:
        return [Check("deps-python:agent", INCOMPLETE, "pip-audit", reason=err or "could not list agent files")]
    if not targets:
        return []
    pip = resolve_tool("SECURITY_SCAN_PIP_AUDIT", "pip-audit")
    osv = resolve_tool("SECURITY_SCAN_OSV_SCANNER", "osv-scanner")
    checks: list[Check] = []
    for kind, path in targets:
        check_name = "deps-python:agent" if len(targets) == 1 else "deps-python:" + str(path.relative_to(root))
        if kind == "pyproject":
            if isinstance(pip, Path):
                checks.append(audit_with_pip(path, root, pip, timeout, project=True, name=check_name))
            else:
                checks.append(
                    Check(
                        check_name,
                        INCOMPLETE,
                        "pip-audit",
                        reason="pip-audit not found (pyproject.toml has no lockfile for osv-scanner)",
                    )
                )
            continue
        if kind == "requirements" and isinstance(pip, Path):
            checks.append(audit_with_pip(path, root, pip, timeout, project=False, name=check_name))
            continue
        if isinstance(osv, Path):
            checks.append(audit_with_osv(path, root, osv, timeout, name=check_name))
            continue
        if isinstance(pip, Path):
            checks.append(audit_with_pip(path, root, pip, timeout, project=False, name=check_name))
            continue
        checks.append(Check(check_name, INCOMPLETE, "pip-audit", reason="pip-audit and osv-scanner not found"))
    return checks


def overall_state(checks: list[Check]) -> str:
    if not checks:
        return INCOMPLETE
    if any(check.state == INCOMPLETE for check in checks):
        return INCOMPLETE
    if any(check.state == FINDINGS for check in checks):
        return FINDINGS
    if all(check.state == CLEAN for check in checks):
        return CLEAN
    return INCOMPLETE


def exit_code_for(state: str) -> int:
    if state == CLEAN:
        return 0
    if state == FINDINGS:
        return 1
    return 2


def render_report(checks: list[Check]) -> str:
    parts = [check.render() for check in checks]
    parts.append(f"overall: {overall_state(checks)}")
    return "\n".join(parts) + "\n"


def scan(root: Path, timeout: int, secrets: str) -> list[Check]:
    root = root.resolve()
    checks: list[Check] = []
    checks.extend(scan_secrets(root, timeout, secrets))
    checks.extend(audit_rust(root, timeout))
    checks.extend(audit_python(root, timeout))
    return checks


def default_root() -> Path:
    code, stdout, _timed_out = run_command(["git", "rev-parse", "--show-toplevel"], timeout=20)
    if code == 0:
        text = stdout.decode("utf-8", "replace").strip()
        if text:
            return Path(text)
    return Path.cwd()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Report-only security scan. Does not modify the tree.")
    parser.add_argument("--root", type=Path, default=None, help="repository root (default: git toplevel)")
    parser.add_argument("--timeout", type=int, default=180, help="per-check timeout in seconds")
    parser.add_argument(
        "--secrets",
        choices=("auto", "builtin", "gitleaks", "trufflehog"),
        default="auto",
        help="secret scanner (default: gitleaks, else trufflehog, else built-in patterns)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = args.root if args.root is not None else default_root()
    if not root.is_dir():
        print(f"secrets-worktree: {INCOMPLETE} (builtin)")
        print("  reason=root is not a directory")
        print(f"overall: {INCOMPLETE}")
        return 2
    try:
        checks = scan(root, args.timeout, args.secrets)
        report = render_report(checks)
    except Exception as exc:
        # The exception text is scrubbed. A failure here did not finish the scan.
        print(f"overall: {INCOMPLETE}")
        print(f"  reason=scan failed ({type(exc).__name__}: {scrub(str(exc))[:200]})")
        return 2
    sys.stdout.write(report)
    return exit_code_for(overall_state(checks))


if __name__ == "__main__":
    sys.exit(main())
