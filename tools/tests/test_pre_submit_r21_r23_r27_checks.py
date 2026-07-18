#!/usr/bin/env python3
"""Pre-submit integration coverage for R21/R23/R27 gate wiring."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"

R27_TOOL = ROOT / "tools" / "adjacent-finding-disclosure-check.py"
R23_TOOL = ROOT / "tools" / "comparative-baseline-check.py"
R21_TOOL = ROOT / "tools" / "permanent-impact-five-ask-template-check.py"


def _workspace(root: Path) -> Path:
    ws = root / "audits" / "demo"
    (ws / "submissions" / "paste_ready").mkdir(parents=True)
    (ws / "poc-tests" / "case").mkdir(parents=True)
    return ws


def _run(draft: Path, ws: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(ws.parent)
    env["TARGET_PLATFORM"] = "auto"
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


def _base(extra: str = "") -> str:
    extra = textwrap.dedent(extra).strip()
    return textwrap.dedent(
        f"""
        # Validator path bug allows direct loss of user funds

        **Severity:** High
        **Rubric:** Direct loss of user funds.
        **Dollar impact:** $500,000 of user funds.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.
        PoC: `poc-tests/case`

        ## Impact

        Non-self impact demonstrated: victim LP funds are debited, and funds the attacker does not control are lost.

        ## Impact Contract

        - Victim: vault LPs
        - Source proof: src/Vault.sol:90-138
        - Harness scaffold: poc-tests/case/poc_test.go
        - selected_impact: Direct loss of user funds
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: admin-only path excluded
        - stop_condition: stop if proof no longer debits victim funds

        {extra}
        """
    ).strip() + "\n"


def _write_case(ws: Path, extra: str) -> Path:
    (ws / "poc-tests" / "case" / "poc_test.go").write_text(
        "package poc\nfunc TestX(t *testing.T){ app.BaseApp.FinalizeBlock(req) }\n",
        encoding="utf-8",
    )
    draft = ws / "submissions" / "paste_ready" / "candidate.md"
    draft.write_text(_base(extra), encoding="utf-8")
    return draft


def _require_tool(testcase: unittest.TestCase, tool: Path) -> None:
    if not tool.exists():
        testcase.skipTest(f"{tool.name} is not present in this workspace")


def _assert_check_blocks(testcase: unittest.TestCase, stdout: str, check_no: int, label: str) -> None:
    pattern = rf"❌\s+{check_no}\.\s+{re.escape(label)} blocked"
    testcase.assertRegex(stdout, pattern, stdout)


def _assert_check_passes(testcase: unittest.TestCase, stdout: str, check_no: int, label: str) -> None:
    pattern = rf"✅\s+{check_no}\.\s+{re.escape(label)}:"
    testcase.assertRegex(stdout, pattern, stdout)


class PreSubmitR21R23R27Tests(unittest.TestCase):
    def test_r27_missing_adjacent_finding_disclosure_blocks(self) -> None:
        _require_tool(self, R27_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(ws, "Root cause: adjacent liquidation and withdrawal paths share the broken invariant.")
            proc = _run(draft, ws)
            _assert_check_blocks(self, proc.stdout, 59, "R27-ADJACENT-FINDING-DISCLOSURE")

    def test_r27_disclosed_adjacent_findings_pass(self) -> None:
        _require_tool(self, R27_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(
                ws,
                """
                Root cause: adjacent liquidation and withdrawal paths share the broken invariant.

                ## Adjacent Finding Disclosure

                - Adjacent path reviewed: `src/Vault.sol:140` liquidation settlement.
                - Relationship: same invariant family, distinct trigger and victim state.
                - Filing boundary: this report covers only the withdrawal freeze path.
                """,
            )
            proc = _run(draft, ws)
            _assert_check_passes(self, proc.stdout, 59, "R27-ADJACENT-FINDING-DISCLOSURE")

    def test_r23_missing_comparative_baseline_blocks(self) -> None:
        _require_tool(self, R23_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(ws, "Claimed impact: the cap was loosened and causes matching-engine degradation.")
            proc = _run(draft, ws)
            _assert_check_blocks(self, proc.stdout, 65, "R23-COMPARATIVE-BASELINE")

    def test_r23_comparative_baseline_passes(self) -> None:
        _require_tool(self, R23_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(
                ws,
                """
                ## Comparative Baseline

                - Baseline: honest deposit and withdrawal leaves victim shares redeemable.
                - Attack run: same initial state, attacker order first, victim shares become permanently frozen.
                - Measurement method: go test ./poc-tests/case -run TestBaselineVsAttack -count=5.
                - Pass/fail threshold: fail if target/upstream ratio is >= 2x or p95 exceeds 200ms.
                """,
            )
            proc = _run(draft, ws)
            _assert_check_passes(self, proc.stdout, 65, "R23-COMPARATIVE-BASELINE")

    def test_r21_missing_permanent_impact_five_ask_template_blocks(self) -> None:
        _require_tool(self, R21_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(ws, "Selected impact: permanent freezing of user funds.")
            proc = _run(draft, ws)
            _assert_check_blocks(self, proc.stdout, 66, "R21-PERMANENT-IMPACT-5-ASK-TEMPLATE")

    def test_r21_five_ask_template_passes(self) -> None:
        _require_tool(self, R21_TOOL)
        with tempfile.TemporaryDirectory() as tmp:
            ws = _workspace(Path(tmp))
            draft = _write_case(
                ws,
                """
                ## Ask coverage

                - Who is affected: victim LPs and account holders with pending withdrawals.
                - What exact asset/state is frozen: victim LP share state is frozen in `src/Vault.sol`.
                - Why recovery/admin/governance/restart cannot clear it: restart cannot clear the poisoned state and governance cannot recover without migration.
                - Duration/permanence: the lock persists indefinitely until hardfork or state migration.
                - Source/runtime proof: source proof is `src/Vault.sol:90-138`; runtime proof is `TestPermanentFreeze`.

                Selected impact: permanent freezing of user funds.
                """,
            )
            proc = _run(draft, ws)
            _assert_check_passes(self, proc.stdout, 66, "R21-PERMANENT-IMPACT-5-ASK-TEMPLATE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
