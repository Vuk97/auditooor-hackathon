#!/usr/bin/env python3
"""Regression coverage for pre-submit severity calibration."""

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


def _run(draft: Path, ws: Path, severity: str = "Critical") -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(ws.parent)
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
        env=env,
    )


def _base(extra: str = "", severity: str = "Critical") -> str:
    return textwrap.dedent(
        f"""
        # Severity calibration fixture

        **Severity:** {severity}
        **Rubric:** Direct theft of user funds.
        **Dollar impact:** $200,000.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.

        ## Impact

        Non-self impact demonstrated: attacker extracts value they do not own.

        ## Impact Contract

        - Victim: affected users
        - Source proof: src/Vault.sol:100-180
        - Harness scaffold: poc-tests/severity/calibration.t.sol
        - selected_impact: Direct theft of user funds
        - severity_tier: {severity}
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: privileged-only path excluded
        - stop_condition: stop if exploit no longer extracts value

        {extra}
        """
    ).strip() + "\n"


class PreSubmitSeverityCalibrationTests(unittest.TestCase):
    def test_critical_yield_overclaim_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base("The extracted residual is unclaimed yield, not user funds."),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("71. SEVERITY-CALIBRATION blocked", proc.stdout, proc.stdout)
            self.assertIn("critical_claim_maps_to_unclaimed_yield_not_direct_user_funds", proc.stdout, proc.stdout)

    def test_high_network_claim_warns_when_multivalidator_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base("Network-level liveness failure in FinalizeBlock.", severity="High"),
                encoding="utf-8",
            )
            proc = _run(draft, ws, severity="High")
            self.assertIn("71. SEVERITY-CALIBRATION:", proc.stdout, proc.stdout)
            self.assertIn("pass-with-advisory", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
