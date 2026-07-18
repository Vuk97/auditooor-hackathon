#!/usr/bin/env python3
"""Hermetic tests for tools/medusa-fuzz.sh."""
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
TOOL = ROOT / "tools" / "medusa-fuzz.sh"
FIXTURE = ROOT / "tools" / "tests" / "fixtures" / "fuzz_wrappers" / "vulnerable"


def write_executable(path: Path, body: str) -> None:
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def minimal_path(fake_bin: Path) -> str:
    return os.pathsep.join([str(fake_bin), "/usr/bin", "/bin", "/usr/sbin", "/sbin"])


def copy_fixture_workspace(dst: Path) -> Path:
    workspace = dst / "workspace"
    shutil.copytree(FIXTURE, workspace)
    return workspace


class MedusaFuzzTest(unittest.TestCase):
    def test_missing_binary_writes_tool_unavailable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            env = os.environ.copy()
            env["PATH"] = minimal_path(root / "bin")
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "tool-unavailable")
            self.assertIn("medusa not found", payload["reason"])
            self.assertFalse(payload["invoked"])

    def test_env_skip_writes_skipped_artifact_without_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "medusa-invoked.marker"
            write_executable(
                fake_bin / "medusa",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  *) : > "{marker}"; printf 'medusa shim called: %s\\n' "$*"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_DEEP_SKIP_MEDUSA"] = "1"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "skipped")
            self.assertIn("AUDITOOOR_DEEP_SKIP_MEDUSA=1", payload["reason"])
            self.assertFalse(marker.exists())
            self.assertFalse(payload["invoked"])

    def test_path_shim_is_invoked_and_artifact_captures_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "medusa-invoked.marker"
            write_executable(
                fake_bin / "medusa",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  *) : > "{marker}"; printf 'medusa shim called: %s\\n' "$*"
                     # Emit a Test summary line so the execution floor is met.
                     printf 'Test summary: 2 test(s) passed, 0 test(s) failed\\n'
                     exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(marker.exists())
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["tool"]["path"], str(fake_bin / "medusa"))
            self.assertIn("medusa shim called", payload["stdout"])
            self.assertEqual(payload["args"], ["fuzz", "--config", "medusa.json"])

    def test_bare_resolved_binary_invocation_is_not_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "medusa-invoked.marker"
            write_executable(
                fake_bin / "medusa",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  "") : > "{marker}"; echo "missing medusa command" >&2; exit 64 ;;
                  *) printf 'medusa shim called: %s\\n' "$*"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(marker.exists())
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertNotEqual(payload["status"], "ok")
            self.assertEqual(payload["status"], "engine-error")
            self.assertEqual(payload["reason"], "medusa exited with code 64")
            self.assertTrue(payload["invoked"])
            self.assertEqual(payload["engine_rc"], 64)
            self.assertEqual(payload["args"], [])
            self.assertEqual(payload["tool"]["path"], str(fake_bin / "medusa"))
            self.assertIn("missing medusa command", payload["stderr"])

    def test_no_fuzz_targets_is_typed_successful_no_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "medusa",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  *) echo "error Failed to start fuzzer"; echo "no assertion, property, optimization, or custom tests were found to fuzz"; exit 6 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            # C1: a no-target run must NOT be recorded as ENGINE_STATUS=ok (silent
            # false-OK). It gets its own status so coverage gates cannot mistake an
            # unexecuted property harness for a real pass. invoked=False accordingly.
            self.assertEqual(payload["status"], "no-target")
            self.assertEqual(payload["engine_rc"], 0)
            self.assertFalse(payload["invoked"])
            self.assertIn("no-target", payload["reason"])
            self.assertIn("no assertion", payload["stdout"])


    def test_silent_rc0_without_test_summary_is_no_execution(self) -> None:
        """Regression: medusa exits 0 but produces no 'Test summary:' line.
        The execution floor is not met so status must be 'no-execution',
        never 'ok'. A no-execution artifact must NOT certify as a successful
        deep-engine run."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "medusa",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  # Exits 0 but emits only a setup message - no Test summary line.
                  *) echo "medusa: compiling project..."; echo "medusa: done"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertEqual(
                payload["status"],
                "no-execution",
                "medusa rc=0 without Test summary must produce status=no-execution, not ok",
            )
            self.assertEqual(payload["engine_rc"], 0)
            self.assertIn("no test summary", payload["reason"].lower())


    def test_sleeping_engine_times_out_and_writes_timeout_artifact(self) -> None:
        """A medusa binary that sleeps longer than the per-harness timeout must be
        killed by the timeout wrapper.  The runner must exit 0 (so the
        all-harnesses loop continues) and write an artifact with status='timeout'
        and invoked=True (the binary was found and started)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "medusa",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "medusa 1.0-test"; exit 0 ;;
                  # Sleeps "forever" - the timeout wrapper must kill this.
                  *) sleep 300; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            # Use a very short timeout so the test finishes quickly.
            env["AUDITOOOR_DEEP_MEDUSA_TIMEOUT"] = "2"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "fuzz", "--config", "medusa.json"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, f"runner must exit 0 on timeout; stderr: {proc.stderr}")
            payload = json.loads((workspace / ".auditooor" / "medusa" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "timeout", payload)
            self.assertIn("timeout", payload["reason"].lower())
            # invoked=True because the binary was resolved and started before being killed.
            self.assertTrue(payload["invoked"])


if __name__ == "__main__":
    unittest.main()
