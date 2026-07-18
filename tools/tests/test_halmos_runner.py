#!/usr/bin/env python3
"""Hermetic tests for tools/halmos-runner.sh."""
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
TOOL = ROOT / "tools" / "halmos-runner.sh"
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


class HalmosRunnerTest(unittest.TestCase):
    def test_missing_binary_writes_tool_unavailable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            env = os.environ.copy()
            env["PATH"] = minimal_path(root / "bin")
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "tool-unavailable")
            self.assertIn("halmos not found", payload["reason"])
            self.assertFalse(payload["invoked"])
            self.assertIsNone(payload["tool"]["path"])

    def test_env_skip_writes_skipped_artifact_without_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "halmos-invoked.marker"
            write_executable(
                fake_bin / "halmos",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) : > "{marker}"; printf '%s\\n' "halmos shim called: $*" "[PASS] check_vault_symbolic(uint256)" "{HALMOS_SUCCESS_SUMMARY}; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_DEEP_SKIP_HALMOS"] = "1"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--function", "check_"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "skipped")
            self.assertIn("AUDITOOOR_DEEP_SKIP_HALMOS=1", payload["reason"])
            self.assertFalse(marker.exists())
            self.assertFalse(payload["invoked"])

    def test_path_shim_is_invoked_and_artifact_captures_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "halmos-invoked.marker"
            write_executable(
                fake_bin / "halmos",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) : > "{marker}"; printf '%s\\n' "halmos shim called: $*" "[PASS] check_vault_symbolic(uint256)" "{HALMOS_SUCCESS_SUMMARY}; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--function", "check_"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(marker.exists())
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["tool"]["path"], str(fake_bin / "halmos"))
            self.assertIn("halmos shim called", payload["stdout"])
            self.assertIn(HALMOS_SUCCESS_SUMMARY, payload["stdout"])
            # Bug B fix: --loop bound is injected automatically unless already present.
            args = payload["args"]
            self.assertIn("--contract", args)
            self.assertIn("--function", args)
            self.assertIn("--loop", args, "halmos-runner must inject --loop bound (Bug B fix)")
            loop_idx = args.index("--loop")
            self.assertTrue(args[loop_idx + 1].isdigit(), "--loop value must be a number")

    def test_silent_rc0_without_symbolic_summary_is_not_ok(self) -> None:
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
                  *) exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--function", "check_"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["engine_rc"], 0)
            self.assertEqual(payload["stdout"], "")
            self.assertEqual(payload["stderr"], "")
            self.assertNotEqual(payload["status"], "ok")

    def test_no_symbolic_tests_is_typed_successful_no_target(self) -> None:
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
                  *) echo "ERROR    No tests with --match-contract '' --match-test '^(check|invariant)_.*'"; exit 1 ;;
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
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["engine_rc"], 0)
            self.assertIn("no-target", payload["reason"])
            self.assertIn("No tests with", payload["stdout"])

    def test_foundry_root_and_custom_out_are_forwarded_to_halmos(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            (workspace / "foundry.toml").write_text(
                textwrap.dedent(
                    """
                    [profile.default]
                    src = "src"
                    out = "src/out"
                    libs = ["lib"]
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) printf '%s\\n' "halmos shim called: $*" "[PASS] check_vault_symbolic(uint256)" "Symbolic test result: 1 passed; 0 failed; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault"],
                cwd=workspace,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            args = payload["args"]
            self.assertIn("--contract", args)
            self.assertIn("--root", args)
            self.assertIn("--forge-build-out", args)
            self.assertIn("src/out", args)
            # Bug B fix: --loop bound injected when not already present.
            self.assertIn("--loop", args, "halmos-runner must inject --loop bound (Bug B fix)")
            loop_idx = args.index("--loop")
            self.assertTrue(args[loop_idx + 1].isdigit(), "--loop value must be a number")
            self.assertIn("--forge-build-out src/out", payload["command"])
            self.assertIn(HALMOS_SUCCESS_SUMMARY, payload["stdout"])

    def test_explicit_root_and_build_out_are_not_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            (workspace / "foundry.toml").write_text(
                textwrap.dedent(
                    """
                    [profile.default]
                    src = "src"
                    out = "src/out"
                    libs = ["lib"]
                    """
                ).lstrip(),
                encoding="utf-8",
            )
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "halmos",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "halmos 0.0-test"; exit 0 ;;
                  *) printf '%s\\n' "halmos shim called: $*" "[PASS] check_vault_symbolic(uint256)" "Symbolic test result: 1 passed; 0 failed; time: 0.01s"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                [
                    "bash",
                    str(TOOL),
                    str(workspace),
                    "--root",
                    "/tmp/explicit-root",
                    "--forge-build-out",
                    "custom-out",
                    "--contract",
                    "Vault",
                ],
                cwd=workspace,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            args = payload["args"]
            self.assertEqual(args.count("--root"), 1, "explicit --root must not be duplicated")
            self.assertEqual(args.count("--forge-build-out"), 1, "explicit --forge-build-out must not be duplicated")
            # Check required elements are present and in correct relative order.
            self.assertIn("--root", args)
            self.assertEqual(args[args.index("--root") + 1], "/tmp/explicit-root")
            self.assertIn("--forge-build-out", args)
            self.assertEqual(args[args.index("--forge-build-out") + 1], "custom-out")
            # Bug B fix: --loop bound injected when not already present.
            self.assertIn("--loop", args, "halmos-runner must inject --loop bound (Bug B fix)")
            self.assertEqual(args.count("--loop"), 1, "--loop must not be duplicated")
            self.assertIn(HALMOS_SUCCESS_SUMMARY, payload["stdout"])


    def test_sleeping_engine_times_out_and_writes_timeout_artifact(self) -> None:
        """A halmos binary that sleeps longer than the per-harness timeout must be
        killed by the timeout wrapper.  The runner must exit 0 (so the
        all-harnesses loop continues) and write an artifact with status='timeout'
        and invoked=True (the binary was found and started)."""
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
                  # Sleeps "forever" - the timeout wrapper must kill this.
                  *) sleep 300; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            # Use a very short timeout so the test finishes quickly.
            env["AUDITOOOR_DEEP_HALMOS_TIMEOUT"] = "2"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, f"runner must exit 0 on timeout; stderr: {proc.stderr}")
            payload = json.loads((workspace / ".auditooor" / "halmos" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "timeout", payload)
            self.assertIn("timeout", payload["reason"].lower())
            # invoked=True because the binary was resolved and started before being killed.
            self.assertTrue(payload["invoked"])


if __name__ == "__main__":
    unittest.main()
