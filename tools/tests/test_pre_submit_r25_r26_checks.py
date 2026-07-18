#!/usr/bin/env python3
"""Regression coverage for pre-submit R25/R26 enforcement."""

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
    (ws / "poc-tests" / "case").mkdir(parents=True)
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
        # Traversal bug in CLOB leads to matching-engine degradation

        **Severity:** High
        **Rubric:** Matching-engine degradation.
        **Dollar impact:** $500,000 of user funds.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.
        PoC: `poc-tests/case`

        ## Impact

        Non-self impact demonstrated: victim LP funds are debited, and funds the attacker does not control are transferred.

        ## Impact Contract

        - Victim: vault LPs
        - Source proof: src/Vault.sol:90-138
        - Harness scaffold: poc-tests/case/poc_test.go
        - selected_impact: Direct theft of user funds
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: admin-only path excluded
        - stop_condition: stop if proof no longer drains funds

        {extra}
        """
    ).strip() + "\n"


class PreSubmitR25R26Tests(unittest.TestCase):
    def test_r25_local_only_downstream_claim_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            (ws / "poc-tests" / "case" / "poc_test.go").write_text(
                "package poc\nfunc TestX(t *testing.T){ k.ProcessSingleMatch(ctx, match) }\n",
                encoding="utf-8",
            )
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("Claimed downstream impact: matching-engine degradation."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("63. R25-DEFENSE-IN-DEPTH-TRAVERSAL blocked", proc.stdout, proc.stdout)

    def test_r25_traversal_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            (ws / "poc-tests" / "case" / "poc_test.go").write_text(
                "package poc\nfunc TestX(t *testing.T){ app.BaseApp.FinalizeBlock(req) }\n",
                encoding="utf-8",
            )
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("Claimed downstream impact: matching-engine degradation."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("63. R25-DEFENSE-IN-DEPTH-TRAVERSAL:", proc.stdout, proc.stdout)
            self.assertIn("pass-defense-traversal", proc.stdout, proc.stdout)

    def test_r26_direct_keeper_msg_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            (ws / "poc-tests" / "case" / "poc_test.go").write_text(
                "package poc\nfunc TestX(t *testing.T){ app.ClobKeeper.HandleMsgPlaceOrder(ctx, msg) }\n",
                encoding="utf-8",
            )
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("MsgPlaceOrder causes fund loss."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("64. R26-ANTE-HANDLER-TRAVERSAL blocked", proc.stdout, proc.stdout)
            self.assertIn("fail-ante-bypass", proc.stdout, proc.stdout)

    def test_r26_ante_traversal_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            (ws / "poc-tests" / "case" / "poc_test.go").write_text(
                "package poc\nfunc TestX(t *testing.T){ app.BaseApp.CheckTx(req) }\n",
                encoding="utf-8",
            )
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(_base("MsgPlaceOrder causes fund loss and traverses ValidateNestedMsg."), encoding="utf-8")
            proc = _run(draft, ws)
            self.assertIn("64. R26-ANTE-HANDLER-TRAVERSAL:", proc.stdout, proc.stdout)
            self.assertIn("pass-ante-traversal", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
