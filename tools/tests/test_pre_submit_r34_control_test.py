#!/usr/bin/env python3
"""Regression coverage for pre-submit R34 control-test enforcement."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _workspace(root: Path) -> Path:
    ws = root / "audits" / "demo"
    (ws / "submissions" / "paste_ready").mkdir(parents=True)
    return ws


def _run(draft: Path, ws: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(ws.parent)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


def _base(extra: str = "") -> str:
    return textwrap.dedent(
        f"""
        # Zero-share residual accounting bug leads to theft of unclaimed yield

        **Severity:** High
        **Rubric:** Theft of unclaimed yield.
        **Dollar impact:** $200,000 of unclaimed yield.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.

        ## Impact

        Non-self impact demonstrated: the attacker controls neither the residual yield pool nor the victim LP class.

        ## Impact Contract

        - Victim: protocol accumulated yield pool
        - Source proof: protocol/x/vault/keeper/deposit.go:70-76
        - Harness scaffold: poc-tests/megavault/zero_share_residual_test.go
        - selected_impact: Theft of unclaimed yield
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: privileged-only path excluded
        - stop_condition: stop if zero-share branch checks existing equity

        {extra}
        """
    ).strip() + "\n"


class PreSubmitR34Tests(unittest.TestCase):
    def test_r34_missing_control_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base("Root cause: zero-share residual capture in the mint branch."),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("69. R34-CONTROL-TEST-DISCIPLINE blocked", proc.stdout, proc.stdout)
            self.assertIn("fail-missing-control-test", proc.stdout, proc.stdout)

    def test_r34_control_test_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base(
                    "Root cause: zero-share residual capture in the mint branch.\n"
                    "Control test: when totalShares remains nonzero, the same workload does not trigger."
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("69. R34-CONTROL-TEST-DISCIPLINE:", proc.stdout, proc.stdout)
            self.assertIn("pass-control-or-rebuttal-present", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
