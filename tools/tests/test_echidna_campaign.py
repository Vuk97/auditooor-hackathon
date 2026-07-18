#!/usr/bin/env python3
"""Hermetic tests for tools/echidna-campaign.sh."""
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
TOOL = ROOT / "tools" / "echidna-campaign.sh"
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


class EchidnaCampaignTest(unittest.TestCase):
    def test_missing_binary_writes_tool_unavailable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            env = os.environ.copy()
            env["PATH"] = minimal_path(root / "bin")
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--config", "echidna.yaml"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "tool-unavailable")
            self.assertIn("echidna not found", payload["reason"])
            self.assertFalse(payload["invoked"])

    def test_env_skip_writes_skipped_artifact_without_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "echidna-invoked.marker"
            write_executable(
                fake_bin / "echidna",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "echidna 2.0-test"; exit 0 ;;
                  *) : > "{marker}"; printf 'echidna shim called: %s\\n' "$*"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            env["AUDITOOOR_DEEP_SKIP_ECHIDNA"] = "1"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--config", "echidna.yaml"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "skipped")
            self.assertIn("AUDITOOOR_DEEP_SKIP_ECHIDNA=1", payload["reason"])
            self.assertFalse(marker.exists())
            self.assertFalse(payload["invoked"])

    def test_path_shim_is_invoked_and_artifact_captures_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "echidna-invoked.marker"
            write_executable(
                fake_bin / "echidna",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "echidna 2.0-test"; exit 0 ;;
                  *)
                    : > "{marker}"
                    printf 'echidna shim called: %s\\n' "$*"
                    printf 'echidna_balance_preserved: passed!\\n'
                    printf 'total calls: 128\\n'
                    exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--config", "echidna.yaml"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(marker.exists())
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["tool"]["path"], str(fake_bin / "echidna"))
            self.assertIn("echidna shim called", payload["stdout"])
            self.assertIn("echidna_balance_preserved: passed!", payload["stdout"])
            self.assertIn("total calls: 128", payload["stdout"])
            self.assertEqual(payload["args"], ["--contract", "Vault", "--config", "echidna.yaml"])

    def test_silent_rc0_fake_is_not_status_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "echidna-invoked.marker"
            write_executable(
                fake_bin / "echidna",
                f"""#!/usr/bin/env bash
                case "${{1:-}}" in
                  --version) echo "echidna 2.0-test"; exit 0 ;;
                  *) : > "{marker}"; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--config", "echidna.yaml"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(marker.exists())
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertNotEqual(payload["status"], "ok", payload)
            self.assertEqual(payload["engine_rc"], 0)
            self.assertEqual(payload["stdout"], "")
            self.assertEqual(payload["stderr"], "")
            self.assertEqual(payload["args"], ["--contract", "Vault", "--config", "echidna.yaml"])

    def test_empty_abi_is_typed_successful_no_target(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "echidna",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "echidna 2.0-test"; exit 0 ;;
                  *) echo "echidna: ABI is empty, are you sure your constructor is right?" >&2; exit 1 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "."],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["engine_rc"], 0)
            self.assertIn("no-target", payload["reason"])
            self.assertIn("ABI is empty", payload["stderr"])


    def test_sleeping_engine_times_out_and_writes_timeout_artifact(self) -> None:
        """An echidna binary that sleeps longer than the per-harness timeout must be
        killed by the timeout wrapper.  The runner must exit 0 (so the
        all-harnesses loop continues) and write an artifact with status='timeout'
        and invoked=True (the binary was found and started)."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            workspace = copy_fixture_workspace(root)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            write_executable(
                fake_bin / "echidna",
                """#!/usr/bin/env bash
                case "${1:-}" in
                  --version) echo "echidna 2.0-test"; exit 0 ;;
                  # Sleeps "forever" - the timeout wrapper must kill this.
                  *) sleep 300; exit 0 ;;
                esac
                """,
            )
            env = os.environ.copy()
            env["PATH"] = minimal_path(fake_bin)
            env["AUDITOOOR_DEEP_BIN_DIR"] = str(root / "w5d1-empty-bin")
            # Use a very short timeout so the test finishes quickly.
            env["AUDITOOOR_DEEP_ECHIDNA_TIMEOUT"] = "2"
            proc = subprocess.run(
                ["bash", str(TOOL), str(workspace), "--contract", "Vault", "--config", "echidna.yaml"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, f"runner must exit 0 on timeout; stderr: {proc.stderr}")
            payload = json.loads((workspace / ".auditooor" / "echidna" / "artifact.json").read_text())
            self.assertEqual(payload["status"], "timeout", payload)
            self.assertIn("timeout", payload["reason"].lower())
            # invoked=True because the binary was resolved and started before being killed.
            self.assertTrue(payload["invoked"])


if __name__ == "__main__":
    unittest.main()
