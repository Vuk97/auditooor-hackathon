#!/usr/bin/env python3
"""Regression coverage for pre-submit R20/R22 enforcement."""

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
        # Runtime fidelity bug in Vault allows draining user funds

        **Severity:** High
        **Rubric:** Direct theft of user funds.
        **Dollar impact:** $500,000 of user funds.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.

        ## Impact

        Non-self impact demonstrated: victim LP funds are debited, and funds the attacker does not control are transferred.

        ## Impact Contract

        - Victim: vault LPs
        - Source proof: src/Vault.sol:90-138
        - Harness scaffold: poc-tests/VaultRacePlan.t.sol
        - selected_impact: Direct theft of user funds
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: admin-only path excluded
        - stop_condition: stop if proof no longer drains funds

        {extra}
        """
    ).strip() + "\n"


class PreSubmitR20R22Tests(unittest.TestCase):
    def test_r20_fault_injection_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("The PoC uses faultyDB and forceFail to trigger the path."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("60. R20-NO-FAULT-INJECTION blocked", proc.stdout, proc.stdout)

    def test_r20_no_fault_tokens_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("The PoC uses unmodified runtime conditions."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("60. R20-NO-FAULT-INJECTION:", proc.stdout, proc.stdout)
            self.assertIn("pass-no-fault-injection", proc.stdout, proc.stdout)

    def test_r22_permanent_claim_without_restart_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("Selected impact: permanent freezing of funds."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("61. R22-RESTART-SURVIVAL-REQUIRED blocked", proc.stdout, proc.stdout)
            self.assertIn("fail-missing-restart-survival", proc.stdout, proc.stdout)

    def test_r22_honest_restart_disclosure_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base("Network halt claim. A process restart clears the staleness; no persistent durability divergence."),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("61. R22-RESTART-SURVIVAL-REQUIRED:", proc.stdout, proc.stdout)
            self.assertIn("pass-honest-disclosure", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
