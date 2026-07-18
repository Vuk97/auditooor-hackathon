#!/usr/bin/env python3
"""Tests for tools/solidity-per-function-halmos-runner.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "solidity-per-function-halmos-runner.py"


class SolidityPerFunctionHalmosRunnerTest(unittest.TestCase):
    def test_runner_executes_each_generated_invocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="per_function_halmos_") as tmp:
            ws = Path(tmp) / "ws"
            manifest = ws / "poc-tests" / "per_function_invariants" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.per_function_invariant_gen.v1",
                        "workspace": str(ws),
                        "function_count": 1,
                        "functions": [
                            {
                                "selector": "Vault.deposit",
                                "harness_contract": "Halmos_Vault_deposit",
                                "harness_path": str(
                                    ws
                                    / "poc-tests"
                                    / "per_function_invariants"
                                    / "Halmos_Vault_deposit.t.sol"
                                ),
                                "halmos_invocation": {
                                    "args": ["--match-contract", "Halmos_Vault_deposit"],
                                },
                            }
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            halmos = fake_bin / "halmos"
            halmos.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${1:-}\" in --version|-v|version) echo 'fake-halmos 1.0'; exit 0 ;; esac\n"
                "echo \"FOUNDRY_TEST=${FOUNDRY_TEST:-}\"\n"
                "echo \"halmos args=$*\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            halmos.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
            env["AUDITOOOR_AUDIT_RUN_FULL_ID"] = "auditrun-test"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--strict", "--json"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.solidity_per_function_halmos.v1")
            self.assertEqual(payload["status"], "ok")
            self.assertEqual(payload["expected_invocation_count"], 1)
            self.assertEqual(payload["executed_invocation_count"], 1)
            self.assertEqual(payload["ok_invocation_count"], 1)
            artifact = Path(payload["invocations"][0]["artifact"])
            self.assertTrue(artifact.is_file())
            artifact_payload = json.loads(artifact.read_text(encoding="utf-8"))
            self.assertEqual(artifact_payload["status"], "ok")
            self.assertEqual(artifact_payload["run_id"], "auditrun-test")
            self.assertEqual(payload["invocations"][0]["foundry_test"], "poc-tests/per_function_invariants")
            self.assertIn(
                "FOUNDRY_TEST=poc-tests/per_function_invariants",
                artifact_payload["stdout"],
            )

    def test_strict_missing_generated_manifest_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="per_function_halmos_missing_") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--strict", "--json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )

            self.assertEqual(proc.returncode, 1)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["reason"], "generated per-function manifest missing or invalid")

    def test_timeout_kills_halmos_process_group_before_next_invocation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="per_function_halmos_timeout_") as tmp:
            root = Path(tmp)
            ws = root / "ws"
            manifest = ws / "poc-tests" / "per_function_invariants" / "manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.per_function_invariant_gen.v1",
                        "workspace": str(ws),
                        "function_count": 1,
                        "functions": [
                            {
                                "selector": "Vault.withdraw",
                                "harness_contract": "Halmos_Vault_withdraw",
                                "harness_path": str(
                                    ws
                                    / "poc-tests"
                                    / "per_function_invariants"
                                    / "Halmos_Vault_withdraw.t.sol"
                                ),
                                "halmos_invocation": {
                                    "args": ["--match-contract", "Halmos_Vault_withdraw"],
                                },
                            }
                        ],
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            fake_bin = root / "bin"
            fake_bin.mkdir()
            leak_marker = root / "child-leaked.marker"
            halmos = fake_bin / "halmos"
            halmos.write_text(
                "#!/usr/bin/env bash\n"
                "case \"${1:-}\" in --version|-v|version) echo 'fake-halmos 1.0'; exit 0 ;; esac\n"
                f"( sleep 2; echo leaked > '{leak_marker}' ) &\n"
                "wait\n",
                encoding="utf-8",
            )
            halmos.chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--timeout-seconds",
                    "1",
                    "--json",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["invocations"][0]["status"], "timeout")
            time.sleep(3)
            self.assertFalse(leak_marker.exists())


if __name__ == "__main__":
    unittest.main()
