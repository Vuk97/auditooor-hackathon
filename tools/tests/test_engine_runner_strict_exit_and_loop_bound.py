#!/usr/bin/env python3
"""
Tests for two generic funnel bugs in the engine runner scripts:

  Bug A (exit-0 masking): echidna-campaign.sh, medusa-fuzz.sh, halmos-runner.sh
    all ended with unconditional `exit 0`, masking engine-error / timeout failures
    from the caller.  Under AUDITOOOR_L37_STRICT=1 the script must exit non-zero
    when the engine returned engine-error or timeout.  Non-STRICT must still exit 0
    (typed artifact is the source of truth; outer loop must not crash).

  Bug B (halmos unbounded): halmos-runner.sh ran halmos with no --loop bound, so
    large handler harnesses would hit the wall-clock timeout with 0 executed tests.
    The script must now inject --loop N (default 8, env-overridable via
    AUDITOOOR_HALMOS_LOOP_BOUND).  If the caller already supplies --loop the runner
    must not duplicate it.  AUDITOOOR_HALMOS_LOOP_BOUND=0 suppresses injection.

Lane: lane-WAVE3-ENGINE-RUNNER-FIXES
r36-rebuttal: funnel-generic-fixes-wave3
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ECHIDNA_TOOL = ROOT / "tools" / "echidna-campaign.sh"
MEDUSA_TOOL = ROOT / "tools" / "medusa-fuzz.sh"
HALMOS_TOOL = ROOT / "tools" / "halmos-runner.sh"
FIXTURE = ROOT / "tools" / "tests" / "fixtures" / "fuzz_wrappers" / "vulnerable"
HALMOS_SUCCESS_SUMMARY = "Symbolic test result: 1 passed; 0 failed"


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def minimal_path(fake_bin: Path) -> str:
    return os.pathsep.join([str(fake_bin), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])


def copy_fixture_workspace(dst: Path) -> Path:
    workspace = dst / "workspace"
    shutil.copytree(FIXTURE, workspace)
    return workspace


def make_error_shim(fake_bin: Path, name: str, version: str, rc: int) -> None:
    """Create a fake binary that exits non-zero (simulates engine-error)."""
    write_executable(
        fake_bin / name,
        f"""#!/usr/bin/env bash
        case "${{1:-}}" in
          --version) echo "{name} {version}"; exit 0 ;;
          *) echo "{name}: fatal: simulated engine failure" >&2; exit {rc} ;;
        esac
        """,
    )


def make_success_shim(fake_bin: Path, name: str, version: str, stdout_line: str) -> None:
    """Create a fake binary that exits 0 with a recognisable success line."""
    write_executable(
        fake_bin / name,
        f"""#!/usr/bin/env bash
        case "${{1:-}}" in
          --version) echo "{name} {version}"; exit 0 ;;
          *) echo "{stdout_line}"; exit 0 ;;
        esac
        """,
    )


# ---------------------------------------------------------------------------
# Bug A: exit-0 masking - echidna
# ---------------------------------------------------------------------------

class EchidnaBugAStrictExitTest(unittest.TestCase):
    """Bug A - echidna-campaign.sh must exit non-zero on engine-error under STRICT."""

    def _run(self, env: dict, rc_expected: int, status_expected: str) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "echidna", "2.0-test", 42)
            env = dict(os.environ, **env)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(ECHIDNA_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "echidna" / "artifact.json").read_text()
            )
            self.assertEqual(
                payload["status"],
                status_expected,
                f"artifact status wrong; stderr={proc.stderr}",
            )
            self.assertEqual(
                proc.returncode,
                rc_expected,
                f"script exit code wrong ({proc.returncode!r}); status={payload['status']}; "
                f"stderr={proc.stderr}",
            )

    def test_engine_error_strict_exits_nonzero(self) -> None:
        """Under AUDITOOOR_L37_STRICT=1 an engine-error shim must produce rc != 0."""
        # This test FAILED before the Bug A fix (script always returned 0).
        self._run(
            env={"AUDITOOOR_L37_STRICT": "1"},
            rc_expected=42,  # engine rc propagated
            status_expected="engine-error",
        )

    def test_engine_error_non_strict_exits_zero(self) -> None:
        """Without STRICT mode an engine-error must still exit 0 (typed artifact)."""
        self._run(
            env={"AUDITOOOR_L37_STRICT": "0"},
            rc_expected=0,
            status_expected="engine-error",
        )

    def test_engine_error_strict_unset_exits_zero(self) -> None:
        """AUDITOOOR_L37_STRICT absent defaults to non-strict: exit 0."""
        env = dict(os.environ)
        env.pop("AUDITOOOR_L37_STRICT", None)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "echidna", "2.0-test", 7)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(ECHIDNA_TOOL), str(workspace)],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, f"non-strict must exit 0; stderr={proc.stderr}")


# ---------------------------------------------------------------------------
# Bug A: exit-0 masking - medusa
# ---------------------------------------------------------------------------

class MedusaBugAStrictExitTest(unittest.TestCase):
    """Bug A - medusa-fuzz.sh must exit non-zero on engine-error under STRICT."""

    def test_engine_error_strict_exits_nonzero(self) -> None:
        """Under AUDITOOOR_L37_STRICT=1 a medusa engine-error shim must produce rc != 0."""
        # This test FAILED before the Bug A fix.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "medusa", "1.0-test", 33)
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(MEDUSA_TOOL), str(workspace), "fuzz"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "medusa" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "engine-error")
            self.assertEqual(
                proc.returncode, 33,
                f"STRICT engine-error must propagate rc=33; got {proc.returncode}; stderr={proc.stderr}",
            )

    def test_engine_error_non_strict_exits_zero(self) -> None:
        """Without STRICT mode a medusa engine-error exits 0 (typed artifact)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "medusa", "1.0-test", 33)
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "0"
            proc = subprocess.run(
                ["bash", str(MEDUSA_TOOL), str(workspace), "fuzz"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "medusa" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "engine-error")
            self.assertEqual(proc.returncode, 0, f"non-strict must exit 0; stderr={proc.stderr}")

    def test_tool_unavailable_strict_still_exits_zero(self) -> None:
        """tool-unavailable is a typed clean skip even under STRICT: exit 0."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            env = dict(os.environ)
            env["PATH"] = minimal_path(root / "bin")
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(MEDUSA_TOOL), str(workspace)],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "medusa" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "tool-unavailable")
            self.assertEqual(
                proc.returncode, 0,
                "tool-unavailable must exit 0 even under STRICT (engine was not invoked)",
            )


# ---------------------------------------------------------------------------
# Bug A: exit-0 masking - halmos
# ---------------------------------------------------------------------------

class HalmosBugAStrictExitTest(unittest.TestCase):
    """Bug A - halmos-runner.sh must exit non-zero on engine-error under STRICT."""

    def test_engine_error_strict_exits_nonzero(self) -> None:
        """Under AUDITOOOR_L37_STRICT=1 a halmos engine-error shim must produce rc != 0."""
        # This test FAILED before the Bug A fix.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "halmos", "0.1-test", 19)
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "engine-error")
            self.assertNotEqual(
                proc.returncode, 0,
                f"STRICT engine-error must exit non-zero; stderr={proc.stderr}",
            )
            self.assertEqual(
                proc.returncode, 19,
                f"STRICT engine-error must propagate the engine rc; got {proc.returncode}",
            )

    def test_engine_error_non_strict_exits_zero(self) -> None:
        """Without STRICT mode a halmos engine-error exits 0 (typed artifact)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            make_error_shim(fake_bin, "halmos", "0.1-test", 19)
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "0"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "engine-error")
            self.assertEqual(
                proc.returncode, 0,
                f"non-strict engine-error must exit 0; got {proc.returncode}; stderr={proc.stderr}",
            )

    def test_timeout_strict_exits_nonzero(self) -> None:
        """Under AUDITOOOR_L37_STRICT=1 a timeout must produce non-zero exit code."""
        # This test FAILED before the Bug A fix.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) sleep 300; exit 0 ;;
                esac
                """,
            )
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_DEEP_HALMOS_TIMEOUT"] = "2"
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
                timeout=30,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "timeout")
            self.assertNotEqual(
                proc.returncode, 0,
                f"STRICT timeout must exit non-zero; got {proc.returncode}; stderr={proc.stderr}",
            )

    def test_timeout_non_strict_exits_zero(self) -> None:
        """Without STRICT mode a halmos timeout must still exit 0 (typed artifact)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) sleep 300; exit 0 ;;
                esac
                """,
            )
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_DEEP_HALMOS_TIMEOUT"] = "2"
            env["AUDITOOOR_L37_STRICT"] = "0"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
                timeout=30,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "timeout")
            self.assertEqual(
                proc.returncode, 0,
                f"non-strict timeout must exit 0; got {proc.returncode}; stderr={proc.stderr}",
            )

    def test_tool_unavailable_strict_still_exits_zero(self) -> None:
        """tool-unavailable exits 0 even under STRICT (engine was not found/invoked)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            env = dict(os.environ)
            env["PATH"] = minimal_path(root / "bin")
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace)],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "tool-unavailable")
            self.assertEqual(
                proc.returncode, 0,
                "tool-unavailable must exit 0 even under STRICT (engine was not invoked)",
            )

    def test_ok_status_strict_exits_zero(self) -> None:
        """A successful halmos run (status=ok) exits 0 even under STRICT."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) printf '%s\\n' "[PASS] check_vault(uint256)" "{HALMOS_SUCCESS_SUMMARY}; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = dict(os.environ)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_L37_STRICT"] = "1"
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(
                proc.returncode, 0,
                f"status=ok must exit 0 even under STRICT; stderr={proc.stderr}",
            )


# ---------------------------------------------------------------------------
# Bug B: halmos --loop bound injection
# ---------------------------------------------------------------------------

class HalmosBugBLoopBoundTest(unittest.TestCase):
    """Bug B - halmos-runner.sh must inject a bounded --loop argument by default."""

    def _run_halmos(self, extra_env: dict, extra_args: list[str]) -> tuple[int, dict, list[str]]:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) printf '%s\\n' "[PASS] check_vault(uint256)" "{HALMOS_SUCCESS_SUMMARY}; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = dict(os.environ, **extra_env)
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(HALMOS_TOOL), str(workspace)] + extra_args,
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            payload = json.loads(
                (workspace / ".auditooor" / "halmos" / "artifact.json").read_text()
            )
            return proc.returncode, payload, payload["args"]

    def test_default_loop_bound_injected(self) -> None:
        """By default halmos-runner must inject --loop N (Bug B fix).

        This test FAILED before the Bug B fix (--loop was absent from args).
        """
        rc, payload, args = self._run_halmos({}, ["--contract", "Vault"])
        self.assertEqual(rc, 0, f"unexpected exit code {rc}")
        self.assertEqual(payload["status"], "ok")
        self.assertIn(
            "--loop",
            args,
            "halmos-runner must inject --loop by default to bound symbolic execution (Bug B fix)",
        )
        loop_idx = args.index("--loop")
        loop_val = args[loop_idx + 1]
        self.assertTrue(
            loop_val.isdigit() and int(loop_val) > 0,
            f"--loop value must be a positive integer; got {loop_val!r}",
        )

    def test_explicit_loop_not_duplicated(self) -> None:
        """If caller already passes --loop N, the runner must NOT add a second --loop."""
        rc, payload, args = self._run_halmos({}, ["--contract", "Vault", "--loop", "5"])
        self.assertEqual(rc, 0)
        self.assertEqual(
            args.count("--loop"), 1,
            f"--loop must appear exactly once when caller supplies it; args={args}",
        )
        # The caller's value must be preserved.
        loop_val = args[args.index("--loop") + 1]
        self.assertEqual(loop_val, "5", f"caller-supplied --loop value must not be overwritten; got {loop_val!r}")

    def test_loop_bound_env_override(self) -> None:
        """AUDITOOOR_HALMOS_LOOP_BOUND=N overrides the default loop depth."""
        rc, payload, args = self._run_halmos(
            {"AUDITOOOR_HALMOS_LOOP_BOUND": "12"},
            ["--contract", "Vault"],
        )
        self.assertEqual(rc, 0)
        self.assertIn("--loop", args)
        loop_val = args[args.index("--loop") + 1]
        self.assertEqual(loop_val, "12", f"env override not respected; got {loop_val!r}")

    def test_loop_bound_zero_suppresses_injection(self) -> None:
        """AUDITOOOR_HALMOS_LOOP_BOUND=0 must suppress --loop injection entirely."""
        rc, payload, args = self._run_halmos(
            {"AUDITOOOR_HALMOS_LOOP_BOUND": "0"},
            ["--contract", "Vault"],
        )
        self.assertEqual(rc, 0)
        self.assertNotIn(
            "--loop",
            args,
            "AUDITOOOR_HALMOS_LOOP_BOUND=0 must suppress --loop injection",
        )

    def test_loop_eq_syntax_not_duplicated(self) -> None:
        """has_engine_arg must recognise --loop=N as already-present (no duplication)."""
        rc, payload, args = self._run_halmos(
            {},
            ["--contract", "Vault", "--loop=3"],
        )
        self.assertEqual(rc, 0)
        loop_entries = [a for a in args if a == "--loop" or a.startswith("--loop=")]
        self.assertEqual(
            len(loop_entries), 1,
            f"--loop must appear exactly once when caller supplies --loop=N; args={args}",
        )


# ---------------------------------------------------------------------------
# Bash -n syntax check for all three scripts (quick gate)
# ---------------------------------------------------------------------------

class EngineRunnerSyntaxTest(unittest.TestCase):
    def _bash_n(self, path: Path) -> None:
        proc = subprocess.run(
            ["bash", "-n", str(path)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"bash -n failed on {path.name}: {proc.stderr}",
        )

    def test_echidna_campaign_syntax(self) -> None:
        self._bash_n(ECHIDNA_TOOL)

    def test_medusa_fuzz_syntax(self) -> None:
        self._bash_n(MEDUSA_TOOL)

    def test_halmos_runner_syntax(self) -> None:
        self._bash_n(HALMOS_TOOL)


if __name__ == "__main__":
    unittest.main()
