#!/usr/bin/env python3
"""Tests for tools/deep-counterexample-record.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "deep-counterexample-record.py"


class DeepCounterexampleRecordTest(unittest.TestCase):
    def test_replayable_counterexample_writes_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "halmos",
                    "--target-function",
                    "Vault.withdraw",
                    "--expected-invariant",
                    "shares must decrease with assets",
                    "--observed-violation",
                    "withdraw leaves shares unchanged",
                    "--replay-command",
                    "forge test --match-test test_withdraw_counterexample",
                    "--generated-forge-test-path",
                    "test/WithdrawCounterexample.t.sol",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema_version"], "auditooor.deep_counterexample.v1")
            self.assertEqual(payload["engine"], "halmos")
            self.assertTrue(payload["promotes_to_poc_work"])
            self.assertTrue(
                (ws / "deep_counterexamples" / "halmos-vault.withdraw.deep_counterexample.v1.json").is_file()
            )

    def test_advisory_without_replay_reason_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "math-model",
                    "--target-function",
                    "Vault.deposit",
                    "--expected-invariant",
                    "shares monotonically increase",
                    "--observed-violation",
                    "model found rounding cliff",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("missing_replay_command_or_impossible_reason", proc.stderr)

    def test_non_replayable_counterexample_requires_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--engine",
                    "crypto-review",
                    "--target-function",
                    "Verifier.verify",
                    "--expected-invariant",
                    "domain separator binds chain",
                    "--observed-violation",
                    "manual review found missing explicit chain binding",
                    "--replay-impossible-reason",
                    "requires specialist proof-system model",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertFalse(payload["promotes_to_poc_work"])
            self.assertEqual(payload["replay_impossible_reason"], "requires specialist proof-system model")


if __name__ == "__main__":
    unittest.main()
