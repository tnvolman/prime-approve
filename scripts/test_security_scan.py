#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Michael McClanahan
# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the report-only security scan.

The planted key is built at runtime. This file must not contain a contiguous
token that GitHub push protection would reject.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "scripts" / "security_scan.py"
SHELL = ROOT / "scripts" / "security_scan.sh"


def load_scan():
    import sys

    spec = importlib.util.spec_from_file_location("security_scan", SCAN)
    module = importlib.util.module_from_spec(spec)
    sys.modules["security_scan"] = module
    spec.loader.exec_module(module)
    return module


scan = load_scan()


def fake_github_pat() -> str:
    body = "a1B2" + "c3D4" + "e5F6" + "g7H8" + "i9J0" + "k1L2" + "m3N4" + "o5P6" + "q7R8"
    assert len(body) == 36
    return "gh" + "p_" + body


def fake_stripe() -> str:
    return "sk_" + "live_" + "a1B2c3D4e5F6g7H8i9J0"


def fake_aws() -> str:
    # 16 characters from the AWS key alphabet (A-Z and 2-7), entropy above the rule floor.
    return "AK" + "IA" + "W3R6T5Y2A7SDFGHJ"


def fake_google() -> str:
    import base64
    import hashlib

    raw = base64.b64encode(hashlib.sha256(b"prime-approve google fixture").digest()).decode("ascii")
    body = raw.replace("+", "A").replace("/", "B")[:35]
    assert len(body) == 35
    return "AI" + "za" + body


def fake_private_key(kind: str) -> str:
    header = "-----BEGIN " + kind + "PRIVATE KEY-----"
    footer = "-----END " + kind + "PRIVATE KEY-----"
    body = "Ab3Cd9" * 16
    return header + "\n" + body + "\n" + footer + "\n"


def fake_high_entropy() -> str:
    import hashlib

    alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    digest = hashlib.sha256(b"prime-approve high entropy fixture").digest()
    return "".join(alphabet[byte % len(alphabet)] for byte in digest)


def git(repo: Path, *args: str, env: dict | None = None) -> str:
    result = subprocess.run(
        ["git", "--no-pager", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout.strip()


def init_repo(repo: Path) -> dict:
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "scan-test",
            "GIT_AUTHOR_EMAIL": "scan-test@example.com",
            "GIT_COMMITTER_NAME": "scan-test",
            "GIT_COMMITTER_EMAIL": "scan-test@example.com",
        }
    )
    return env


def commit_all(repo: Path, env: dict, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "--no-gpg-sign", "-m", message, env=env)
    return git(repo, "rev-parse", "HEAD")


def run_scan(repo: Path, *extra: str, env: dict | None = None, timeout: int = 120) -> subprocess.CompletedProcess:
    command = ["python3", str(SCAN), "--root", str(repo), *extra]
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(command, capture_output=True, text=True, env=merged, timeout=timeout)


def states(report: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in report.splitlines():
        if line.startswith("  ") or not line.strip():
            continue
        if line.startswith("overall:"):
            found["overall"] = line.split(":", 1)[1].strip()
            continue
        name, rest = line.split(": ", 1)
        found[name] = rest.split(" (", 1)[0]
    return found


class BuiltinPatternTests(unittest.TestCase):
    def test_required_patterns_match_runtime_fixtures(self) -> None:
        token = fake_github_pat()
        stripe = fake_stripe()
        aws = fake_aws()
        google = fake_google()
        pem = fake_private_key("")
        ed25519 = fake_private_key("ED25519 ")
        openssh = fake_private_key("OPENSSH ")
        generic = fake_high_entropy()
        text = "\n".join(
            [
                f"github = '{token}'",
                f"stripe = '{stripe}'",
                f"aws = '{aws}'",
                f"google = '{google}'",
                pem,
                ed25519,
                openssh,
                f"api_key = '{generic}'",
                "hash = 'f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d'",
                "token = 'aaaaaaaaaaaaaaaaaaaa'",
            ]
        )
        rules = {rule for rule, _line, _secret in scan.scan_text(text)}
        self.assertIn("github-pat", rules)
        self.assertIn("stripe-access-token", rules)
        self.assertIn("aws-access-key", rules)
        self.assertIn("google-api-key", rules)
        self.assertIn("private-key", rules)
        self.assertIn("high-entropy", rules)
        self.assertGreaterEqual(scan.shannon_entropy(token), 3.0)
        self.assertGreaterEqual(scan.shannon_entropy(generic), 4.5)
        # A SHA-256 hex string and a repeated placeholder are not findings.
        hashed = scan.scan_text("hash = 'f961b2d1333fb6d7cabfca5deae7b688bc23179427874fba41550e7c6a4a101d'\n")
        self.assertEqual(hashed, [])
        placeholder = scan.scan_text("token = 'aaaaaaaaaaaaaaaaaaaa'\n")
        self.assertEqual(placeholder, [])

    def test_private_key_headers_are_the_same_rule(self) -> None:
        for kind in ("", "ED25519 ", "OPENSSH ", "RSA ", "EC "):
            hits = scan.scan_text(fake_private_key(kind))
            self.assertTrue(any(rule == "private-key" for rule, _line, _secret in hits), kind)


class SecretScanTests(unittest.TestCase):
    def _plant(self, repo: Path, token: str) -> tuple[dict, str]:
        env = init_repo(repo)
        (repo / "notes.txt").write_text("# fixture, not a credential\nvalue = \"%s\"\n" % token, encoding="utf-8")
        first = commit_all(repo, env, "add fixture")
        return env, first

    def test_builtin_catches_planted_key_in_worktree_and_history(self) -> None:
        import tempfile

        token = fake_github_pat()
        with tempfile.TemporaryDirectory(prefix="scan-secret-") as tmp:
            repo = Path(tmp)
            _env, first = self._plant(repo, token)
            before = git(repo, "status", "--porcelain")
            head = git(repo, "rev-parse", "HEAD")
            result = run_scan(repo, "--secrets", "builtin", "--timeout", "60")
            self.assertEqual(git(repo, "status", "--porcelain"), before)
            self.assertEqual(git(repo, "rev-parse", "HEAD"), head)
            self.assertNotIn(token, result.stdout)
            self.assertNotIn(token, result.stderr)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.FINDINGS)
            self.assertEqual(report_states["secrets-history"], scan.FINDINGS)
            self.assertEqual(result.returncode, 1)
            expected = scan.fingerprint(token)
            self.assertIn(expected, result.stdout)
            self.assertIn("rule=github-pat", result.stdout)
            self.assertIn("file=notes.txt", result.stdout)
            self.assertIn("commit=working-tree", result.stdout)
            self.assertIn(f"commit={first}", result.stdout)
            self.assertIn("line=2", result.stdout)
            self.assertNotIn(token, SCAN.read_text(encoding="utf-8"))

    def test_history_keeps_a_key_removed_from_the_worktree(self) -> None:
        import tempfile

        token = fake_github_pat()
        with tempfile.TemporaryDirectory(prefix="scan-hist-") as tmp:
            repo = Path(tmp)
            env, first = self._plant(repo, token)
            (repo / "notes.txt").write_text("gone\n", encoding="utf-8")
            commit_all(repo, env, "remove fixture")
            result = run_scan(repo, "--secrets", "builtin", "--timeout", "60")
            self.assertNotIn(token, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.CLEAN)
            self.assertEqual(report_states["secrets-history"], scan.FINDINGS)
            self.assertIn(f"commit={first}", result.stdout)
            self.assertIn(scan.fingerprint(token), result.stdout)

    def test_gitleaks_catches_the_same_fixture_when_installed(self) -> None:
        import tempfile

        if not isinstance(scan.resolve_tool("SECURITY_SCAN_GITLEAKS", "gitleaks"), Path):
            self.skipTest("gitleaks is not installed")
        token = fake_github_pat()
        with tempfile.TemporaryDirectory(prefix="scan-gl-") as tmp:
            repo = Path(tmp)
            _env, first = self._plant(repo, token)
            result = run_scan(repo, "--secrets", "gitleaks", "--timeout", "60")
            self.assertNotIn(token, result.stdout)
            self.assertNotIn(token, result.stderr)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.FINDINGS)
            self.assertEqual(report_states["secrets-history"], scan.FINDINGS)
            self.assertEqual(result.returncode, 1)
            self.assertIn("rule=github-pat", result.stdout)
            self.assertIn("file=notes.txt", result.stdout)
            self.assertIn(scan.fingerprint(token), result.stdout)
            self.assertIn(f"commit={first}", result.stdout)
            self.assertIn("line=2", result.stdout)


class DependencyTests(unittest.TestCase):
    def test_pinned_vulnerable_package_is_findings_not_a_crash(self) -> None:
        import tempfile

        if not isinstance(scan.resolve_tool("SECURITY_SCAN_PIP_AUDIT", "pip-audit"), Path):
            self.skipTest("pip-audit is not installed")
        with tempfile.TemporaryDirectory(prefix="scan-py-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            agent = repo / "agent"
            agent.mkdir()
            (agent / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "pin a known-vulnerable package")
            result = run_scan(repo, "--secrets", "builtin", "--timeout", "90")
            self.assertEqual(result.returncode, 1, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-python:agent"], scan.FINDINGS)
            self.assertNotEqual(report_states["deps-python:agent"], scan.INCOMPLETE)
            self.assertIn("package=pyyaml", result.stdout)
            self.assertIn("version=5.3.1", result.stdout)
            self.assertTrue(
                "PYSEC-2021-142" in result.stdout or "CVE-2020-14343" in result.stdout,
                result.stdout,
            )
            self.assertEqual(report_states["secrets-worktree"], scan.CLEAN)
            self.assertEqual(report_states["secrets-history"], scan.CLEAN)

    def test_vulnerable_rust_lockfile_is_caught(self) -> None:
        import tempfile

        if not isinstance(scan.resolve_tool("SECURITY_SCAN_OSV_SCANNER", "osv-scanner"), Path):
            if not isinstance(scan._cargo_audit_command(), list):
                self.skipTest("neither cargo-audit nor osv-scanner is installed")
        with tempfile.TemporaryDirectory(prefix="scan-rs-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "Cargo.lock").write_text(
                "\n".join(
                    [
                        "# This file is automatically @generated by Cargo.",
                        "# It is not intended for manual editing.",
                        "version = 3",
                        "",
                        "[[package]]",
                        'name = "smallvec"',
                        'version = "1.6.0"',
                        'source = "registry+https://github.com/rust-lang/crates.io-index"',
                        'checksum = "cd7a3662f7b8e59e3bb2a7daf61d7799333cf22b75cfb7d1aace4f6e9d0d6e1d"',
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "pin a known-vulnerable crate")
            result = run_scan(repo, "--secrets", "builtin", "--timeout", "90")
            self.assertEqual(result.returncode, 1, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-rust:Cargo.lock"], scan.FINDINGS)
            self.assertIn("package=smallvec", result.stdout)
            self.assertIn("version=1.6.0", result.stdout)
            self.assertIn("RUSTSEC-2021-0003", result.stdout)
            self.assertIn("kind=vulnerability", result.stdout)

    def test_cargo_audit_warnings_are_findings_labelled_by_kind(self) -> None:
        import tempfile

        report = {
            "vulnerabilities": {
                "found": True,
                "count": 1,
                "list": [
                    {
                        "advisory": {
                            "id": "RUSTSEC-2021-0003",
                            "package": "smallvec",
                            "aliases": ["GHSA-43w2-9j62-hq99"],
                        },
                        "package": {"name": "smallvec", "version": "1.6.0"},
                    }
                ],
            },
            "warnings": {
                "unmaintained": [
                    {
                        "kind": "unmaintained",
                        "package": {"name": "paste", "version": "1.0.15"},
                        "advisory": {"id": "RUSTSEC-2024-0436", "package": "paste", "aliases": []},
                    }
                ],
                "unsound": [
                    {
                        "kind": "unsound",
                        "package": {"name": "event-listener", "version": "5.4.1"},
                        "advisory": {"id": "RUSTSEC-2026-0221", "package": "event-listener"},
                    }
                ],
                "yanked": [
                    {
                        "kind": "yanked",
                        "package": {"name": "yanked-demo", "version": "0.1.0"},
                        "advisory": None,
                    }
                ],
            },
        }
        osv_report = {
            "results": [
                {
                    "packages": [
                        {
                            "package": {"name": "paste", "version": "1.0.15"},
                            "vulnerabilities": [
                                {
                                    "id": "RUSTSEC-2024-0436",
                                    "affected": [
                                        {"database_specific": {"informational": "unmaintained"}}
                                    ],
                                }
                            ],
                        },
                        {
                            "package": {"name": "smallvec", "version": "1.6.0"},
                            "vulnerabilities": [
                                {
                                    "id": "RUSTSEC-2021-0003",
                                    "aliases": ["GHSA-43w2-9j62-hq99"],
                                    "affected": [
                                        {"database_specific": {"informational": None}}
                                    ],
                                }
                            ],
                        },
                        {
                            "package": {"name": "event-listener", "version": "5.4.1"},
                            "vulnerabilities": [
                                {
                                    "id": "RUSTSEC-2026-0221",
                                    "affected": [{"database_specific": {"informational": "unsound"}}],
                                }
                            ],
                        },
                    ]
                }
            ]
        }
        lock_text = "\n".join(
            [
                'name = "paste"',
                'version = "1.0.15"',
                'name = "smallvec"',
                'version = "1.6.0"',
                'name = "event-listener"',
                'version = "5.4.1"',
                'name = "yanked-demo"',
                'version = "0.1.0"',
            ]
        )
        cargo_findings = scan._dep_findings_from_cargo_audit(report, "Cargo.lock", lock_text)
        osv_findings = scan._dep_findings_from_osv(osv_report, "Cargo.lock", lock_text)[0]
        cargo_kinds = {(item.rule, item.package, item.version, item.kind) for item in cargo_findings}
        osv_kinds = {(item.rule, item.package, item.version, item.kind) for item in osv_findings}
        self.assertIn(("RUSTSEC-2021-0003", "smallvec", "1.6.0", "vulnerability"), cargo_kinds)
        self.assertIn(("RUSTSEC-2024-0436", "paste", "1.0.15", "unmaintained"), cargo_kinds)
        self.assertIn(("RUSTSEC-2026-0221", "event-listener", "5.4.1", "unsound"), cargo_kinds)
        self.assertIn(("yanked", "yanked-demo", "0.1.0", "yanked"), cargo_kinds)
        self.assertTrue(osv_kinds <= cargo_kinds)
        self.assertEqual(
            {item.kind for item in osv_findings},
            {"vulnerability", "unmaintained", "unsound"},
        )

        warnings_only = {
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": report["warnings"],
        }
        with tempfile.TemporaryDirectory(prefix="scan-audit-warn-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "Cargo.lock").write_text(lock_text + "\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "lockfile")
            stub = Path(tmp) / "cargo-audit"
            import json

            stub.write_text(
                "#!/bin/sh\ncat <<'JSON'\n%s\nJSON\nexit 0\n" % json.dumps(warnings_only),
                encoding="utf-8",
            )
            stub.chmod(0o755)
            result = run_scan(
                repo,
                "--secrets",
                "builtin",
                "--timeout",
                "30",
                env={"SECURITY_SCAN_CARGO_AUDIT": str(stub)},
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-rust:Cargo.lock"], scan.FINDINGS)
            self.assertNotEqual(report_states["deps-rust:Cargo.lock"], scan.CLEAN)
            self.assertIn("kind=unmaintained", result.stdout)
            self.assertIn("kind=unsound", result.stdout)
            self.assertIn("kind=yanked", result.stdout)
            self.assertIn("rule=RUSTSEC-2024-0436", result.stdout)
            self.assertIn("package=yanked-demo", result.stdout)
            self.assertNotIn("kind=vulnerability", result.stdout)


class IncompleteTests(unittest.TestCase):
    def test_missing_dependency_tool_is_incomplete(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-miss-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            agent = repo / "agent"
            agent.mkdir()
            (agent / "requirements.txt").write_text("pyyaml==6.0.2\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "requirements without a scanner")
            result = run_scan(
                repo,
                "--secrets",
                "builtin",
                "--timeout",
                "30",
                env={
                    "SECURITY_SCAN_PIP_AUDIT": "/no/such/pip-audit",
                    "SECURITY_SCAN_OSV_SCANNER": "/no/such/osv-scanner",
                },
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-python:agent"], scan.INCOMPLETE)
            self.assertEqual(report_states["overall"], scan.INCOMPLETE)
            self.assertNotEqual(report_states["deps-python:agent"], scan.CLEAN)
            self.assertIn("not found", result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.CLEAN)
            self.assertEqual(report_states["secrets-history"], scan.CLEAN)

    def test_trufflehog_result_without_secret_is_incomplete(self) -> None:
        import tempfile

        payload = (
            '{"DetectorName":"GitHub","SourceMetadata":{"Data":{"Filesystem":'
            '{"file":"notes.txt","line":2}}}}\n'
        )
        with self.assertRaises(ValueError):
            scan._trufflehog_findings(payload.encode("utf-8"), Path("/tmp"), "working-tree")
        token = fake_github_pat()
        present = payload.strip()[:-1] + ',"Raw":"' + token + '"}\n'
        found = scan._trufflehog_findings(present.encode("utf-8"), Path("/tmp"), "working-tree")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].fingerprint, scan.fingerprint(token))
        self.assertNotIn(token, found[0].render())
        with tempfile.TemporaryDirectory(prefix="scan-th-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "notes.txt").write_text("nothing here\n", encoding="utf-8")
            commit_all(repo, env, "notes")
            stub = Path(tmp) / "trufflehog"
            stub.write_text(
                "#!/bin/sh\nprintf '%s' '" + payload.replace("'", "'\\''") + "'\nexit 0\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            result = run_scan(
                repo,
                "--secrets",
                "trufflehog",
                "--timeout",
                "30",
                env={"SECURITY_SCAN_TRUFFLEHOG": str(stub)},
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.INCOMPLETE)
            self.assertEqual(report_states["secrets-history"], scan.INCOMPLETE)
            self.assertEqual(report_states["overall"], scan.INCOMPLETE)
            self.assertIn("no secret field", result.stdout)
            for line in result.stdout.splitlines():
                if line.startswith("secrets-"):
                    self.assertNotIn(scan.CLEAN, line)

    def test_missing_secret_tool_is_incomplete(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-miss-sec-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            commit_all(repo, env, "readme")
            result = run_scan(
                repo,
                "--secrets",
                "gitleaks",
                "--timeout",
                "30",
                env={"SECURITY_SCAN_GITLEAKS": "/no/such/gitleaks"},
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.INCOMPLETE)
            self.assertEqual(report_states["secrets-history"], scan.INCOMPLETE)
            self.assertEqual(report_states["overall"], scan.INCOMPLETE)
            for line in result.stdout.splitlines():
                if line.startswith("secrets-"):
                    self.assertNotIn(scan.CLEAN, line)

    def test_unreadable_output_is_incomplete_even_when_exit_code_is_1(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-bad-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            agent = repo / "agent"
            agent.mkdir()
            (agent / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "requirements")
            stub = Path(tmp) / "pip-audit"
            stub.write_text("#!/bin/sh\necho not-json\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            result = run_scan(
                repo,
                "--secrets",
                "builtin",
                "--timeout",
                "30",
                env={
                    "SECURITY_SCAN_PIP_AUDIT": str(stub),
                    "SECURITY_SCAN_OSV_SCANNER": "/no/such/osv-scanner",
                },
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-python:agent"], scan.INCOMPLETE)
            self.assertIn("not readable", result.stdout)

    def test_timeout_is_incomplete(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-time-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            agent = repo / "agent"
            agent.mkdir()
            (agent / "requirements.txt").write_text("pyyaml==6.0.2\n", encoding="utf-8")
            (repo / "README.md").write_text("fixture\n", encoding="utf-8")
            commit_all(repo, env, "requirements")
            stub = Path(tmp) / "pip-audit"
            stub.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
            stub.chmod(0o755)
            result = run_scan(
                repo,
                "--secrets",
                "builtin",
                "--timeout",
                "1",
                env={
                    "SECURITY_SCAN_PIP_AUDIT": str(stub),
                    "SECURITY_SCAN_OSV_SCANNER": "/no/such/osv-scanner",
                },
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["deps-python:agent"], scan.INCOMPLETE)
            self.assertIn("timed out", result.stdout)

    def test_shell_wrapper_reports_missing_tool(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-sh-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "README.md").write_text("hello\n", encoding="utf-8")
            commit_all(repo, env, "readme")
            merged = os.environ.copy()
            merged["SECURITY_SCAN_GITLEAKS"] = "/no/such/gitleaks"
            result = subprocess.run(
                [str(SHELL), "--root", str(repo), "--secrets", "gitleaks", "--timeout", "30"],
                capture_output=True,
                text=True,
                env=merged,
                timeout=60,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(states(result.stdout)["overall"], scan.INCOMPLETE)


class ReportTests(unittest.TestCase):
    def test_clean_repo_exits_zero(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory(prefix="scan-clean-") as tmp:
            repo = Path(tmp)
            env = init_repo(repo)
            (repo / "README.md").write_text("nothing to see\n", encoding="utf-8")
            commit_all(repo, env, "readme")
            result = run_scan(repo, "--secrets", "builtin", "--timeout", "30")
            self.assertEqual(result.returncode, 0, result.stdout)
            report_states = states(result.stdout)
            self.assertEqual(report_states["secrets-worktree"], scan.CLEAN)
            self.assertEqual(report_states["secrets-history"], scan.CLEAN)
            self.assertEqual(report_states["overall"], scan.CLEAN)

    def test_fingerprint_is_not_the_secret(self) -> None:
        token = fake_github_pat()
        digest = scan.fingerprint(token)
        self.assertNotIn(token, digest)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(len(digest), len("sha256:") + 16)


if __name__ == "__main__":
    unittest.main()
