from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKLIST = ROOT / "tools" / "logic-flow-bypass-accounting-worklist.py"


def _write_spec(path: Path, text: str) -> None:
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class LogicFlowBypassAccountingWorklistTest(unittest.TestCase):
    def test_gainsnetwork_accounting_flow_rows_are_corpus_first(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lfb_accounting_") as tmp:
            spec_dir = Path(tmp)
            _write_spec(
                spec_dir / "gains-double-pnl.yaml",
                """
                name: c-01-decrease-position-can-be-abused-to-withdraw-pnl-twice
                source: Solodit #58127 (Pashov Audit Group/GainsNetwork_2025-05-26)
                solodit_id: "58127"
                wiki_title: "[C-01] Decrease position can be abused to withdraw PnL twice"
                wiki_description: |
                  When users decrease their position, executeDecreasePositionSizeMarket
                  accounts available collateral and sends PnL to the trader. The
                  wrong accounting flow lets collateral be withdrawn twice.
                wiki_exploit_scenario: |
                  The bypass depends on a value-flow mismatch between position
                  accounting and the later collateral transfer to the trader.
                """,
            )
            _write_spec(
                spec_dir / "unrelated-access-control.yaml",
                """
                name: owner-only-setter
                source: synthetic
                wiki_title: "Owner setter lacks onlyOwner"
                wiki_description: |
                  This is an access-control issue with no asset movement,
                  collateral accounting, or flow mismatch.
                """,
            )
            out_json = spec_dir / "worklist.json"
            out_md = spec_dir / "worklist.md"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(WORKLIST),
                    "--spec-dir",
                    str(spec_dir),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--print-json",
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.logic_flow_bypass_accounting_worklist.v1")
            self.assertTrue(payload["corpus_first"])
            self.assertFalse(payload["actionable_detector_work"])
            self.assertFalse(payload["promotion_allowed"])
            self.assertFalse(payload["tier_a_detector_closure_claim"])
            self.assertEqual(payload["detectorization_posture"], "CORPUS_FIRST")
            self.assertEqual(payload["task_count"], 1)
            self.assertEqual(payload["gains_network_inspired_count"], 1)

            task = payload["tasks"][0]
            self.assertTrue(task["gains_network_inspired"])
            self.assertEqual(task["bug_class"], "logic-error-flow-bypass")
            self.assertEqual(task["subcase"], "accounting_value_flow")
            self.assertEqual(task["detectorization_readiness"], "not_ready_needs_value_flow_corpus_evidence")
            self.assertEqual(task["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(task["severity"], "none")
            self.assertTrue(task["impact_contract_required"])
            self.assertIn("source function that mutates accounting state", task["required_value_flow_evidence"][0])
            self.assertTrue(any("cannot prove" in reason for reason in task["why_no_detector_yet"]))
            self.assertIn("This is not detector closure", out_md.read_text(encoding="utf-8"))

    def test_broader_non_gains_accounting_value_flow_rows_are_worklisted_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lfb_accounting_") as tmp:
            spec_dir = Path(tmp)
            _write_spec(
                spec_dir / "treasury-balance-tracking-bypass.yaml",
                """
                name: treasury-balance-tracking-bypass-in-feecollector
                source: synthetic
                wiki_title: "Treasury balance tracking bypass in FeeCollector"
                wiki_description: |
                  Fee accounting records the wrong balance before funds are sent
                  to the treasury. A caller can bypass the expected accounting
                  path and leave asset transfers inconsistent with recorded fees.
                """,
            )
            proc = subprocess.run(
                [sys.executable, str(WORKLIST), "--spec-dir", str(spec_dir), "--print-json"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["task_count"], 1)
            self.assertEqual(payload["gains_network_inspired_count"], 0)
            self.assertEqual(payload["non_gains_accounting_value_flow_count"], 1)
            task = payload["tasks"][0]
            self.assertFalse(task["gains_network_inspired"])
            self.assertFalse(task["promotion_allowed"])
            self.assertFalse(task["tier_a_detector_closure_claim"])
            self.assertTrue(any(
                "paired vulnerable and clean fixtures" in item
                for item in task["required_value_flow_evidence"]
            ))

    def test_missing_spec_dir_fails_actionably(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lfb_accounting_") as tmp:
            missing = Path(tmp) / "missing"
            proc = subprocess.run(
                [sys.executable, str(WORKLIST), "--spec-dir", str(missing)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )

            self.assertEqual(proc.returncode, 2)
            self.assertIn("spec dir not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()
