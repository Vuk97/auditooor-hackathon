#!/usr/bin/env python3
"""Tests for mass paste-ready retrofit reporter."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "mass-paste-ready-retrofit.py"
_spec = importlib.util.spec_from_file_location("mass_paste_ready_retrofit", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


COMPLETE = """# Guard bypass allows direct loss of user funds

Severity: High

## Program Impact Mapping

- selected_impact: Direct loss of user funds

## Production Path

BaseApp.FinalizeBlock reaches the vulnerable state.

## Impact Contract

- Victim: user account
- Source proof: src/vault.rs:10-30
- Harness scaffold: poc-tests/case/poc_test.rs
- selected_impact: Direct loss of user funds
- severity_tier: High
- listed_impact_proven: true
- evidence_class: runtime_poc
- oos_traps: none. No admin path is used.
- stop_condition: stop if victim debit no longer occurs.

Non-self impact demonstrated: victim balance is debited and funds the attacker does not control are lost.

## Comparative Baseline

- Baseline: honest run vs attack run.
- Measurement method: go test ./poc-tests/case -run TestBaseline -count=3.
- Pass/fail threshold: fail if victim debit is greater than 0.

### What the tests prove

Full-suite regression PASS: all focused tests pass.
"""


INCOMPLETE = """# Missing validation allows permanent freezing of user funds

Severity: Critical

The same root cause affects a sibling path. A follow-up report will cover it.
The weakened cap is slower than upstream.
Impact: permanent freezing of funds.
"""


class MassPasteReadyRetrofitTests(unittest.TestCase):
    def test_complete_draft_is_ok(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="retrofit_"))
        draft = root / "complete-HIGH.md"
        draft.write_text(COMPLETE, encoding="utf-8")
        payload = mod.build_report(root)
        self.assertEqual(payload["draft_count"], 1)
        self.assertEqual(payload["needs_retrofit_count"], 0, json.dumps(payload, indent=2))

    def test_incomplete_draft_reports_gate_backed_missing_items(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="retrofit_"))
        draft = root / "incomplete-CRITICAL.md"
        draft.write_text(INCOMPLETE, encoding="utf-8")
        payload = mod.build_report(root)
        row = payload["drafts"][0]
        self.assertEqual(row["status"], "needs_retrofit")
        self.assertIn("impact_contract_l27_directives", row["missing"])
        self.assertIn("impact_contract_section", row["missing"])
        self.assertIn("r24_non_self_impact_prose", row["missing"])
        self.assertIn("r27_adjacent_finding_disclosure", row["missing"])
        self.assertIn("r23_comparative_baseline", row["missing"])
        self.assertIn("r21_permanent_impact_five_ask", row["missing"])
        self.assertIn("what_tests_prove", row["missing"])

    def test_gold_template_sections_are_reported(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="retrofit_"))
        gold = root / "gold.md"
        gold.write_text(
            "## Impact Contract\n\n## Program Impact Mapping\n\n## Production Path\n\n## Recommended Fix\n",
            encoding="utf-8",
        )
        draft = root / "draft.md"
        draft.write_text("Severity: Medium\n\n## Impact Contract\n", encoding="utf-8")
        payload = mod.build_report(draft, gold_template=gold)
        row = payload["drafts"][0]
        self.assertIn("Program Impact Mapping", row["gold_template_sections_missing"])
        self.assertIn("Production Path", row["gold_template_sections_missing"])
        self.assertIn("Recommended Fix", row["gold_template_sections_missing"])

    def test_markdown_report_contains_missing_counts(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="retrofit_"))
        (root / "incomplete-CRITICAL.md").write_text(INCOMPLETE, encoding="utf-8")
        payload = mod.build_report(root)
        text = mod.markdown_report(payload)
        self.assertIn("Mass Paste-Ready Retrofit Report", text)
        self.assertIn("impact_contract_l27_directives", text)

    def test_cli_writes_json_and_markdown(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="retrofit_"))
        (root / "incomplete-CRITICAL.md").write_text(INCOMPLETE, encoding="utf-8")
        out_json = root / "report.json"
        out_md = root / "report.md"
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                str(root),
                "--out-json",
                str(out_json),
                "--out-md",
                str(out_md),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(out_json.is_file())
        self.assertTrue(out_md.is_file())
        payload = json.loads(out_json.read_text(encoding="utf-8"))
        self.assertEqual(payload["needs_retrofit_count"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
