#!/usr/bin/env python3
"""Check #25 regressions for OOS prerequisite / root-cause gating.

Base Azul FN5 lesson, generalized: proving downstream impact is not enough
when the missing exploit prerequisite is OOS. High/Critical drafts must prove
the in-scope trigger/root cause before leaning on bridge drain, fund theft, or
other severe impact.
"""
from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _run_pre_submit(draft: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Critical"],
        capture_output=True,
        text=True,
    )


class Check25PoisonedStateTests(unittest.TestCase):
    def test_bridge_drain_without_creation_path_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "fn5_like.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Guardian blacklist fails to cascade, enabling poisoned anchors and bridge drain

                    **Severity:** Critical

                    **Rubric:** Direct theft of user funds.
                    **Dollar impact:** Base bridge TVL at risk.

                    ## Impact

                    OptimismPortal2 finalizes an invalid withdrawal after
                    AnchorStateRegistry accepts descendant G2. The fraudulent
                    game G1 is a blacklisted ancestor, but G2 remains
                    DEFENDER_WINS. A mock verifier demonstrates the final
                    bridge drain after the invalid root exists.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "25. oos-prerequisite-root-cause-missing",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn("Poisoned State Creation Path", proc.stdout)

    def test_bridge_drain_with_in_scope_creation_path_passes_check25(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "root_cause_bridge.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # AggregateVerifier journal replay creates false root accepted by Portal

                    **Severity:** Critical

                    **Rubric:** Direct theft of user funds.
                    **Dollar impact:** Base bridge TVL at risk.

                    ## Impact

                    OptimismPortal2 finalizes an invalid withdrawal after an
                    invalid state root is accepted as DEFENDER_WINS.

                    ## Poisoned State Creation Path

                    This is an in-scope on-chain proof-verification root cause
                    in AggregateVerifier. The attacker uses a permissionless
                    journal replay / domain-separation bypass that is accepted
                    by the contract as a valid proof for the false root claim.
                    The bridge drain is only the downstream impact after this
                    source-level contract bug creates the poisoned state.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "25. OOS prerequisite gate: pass",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("25. oos-prerequisite-root-cause-missing", proc.stdout)

    def test_high_theft_with_privileged_assumption_requires_scope_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "admin_assumption.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Operator does not react, allowing direct theft of vault funds

                    **Severity:** High

                    **Rubric:** Direct theft of any user funds.
                    **Dollar impact:** $500,000 of user funds.

                    ## Impact

                    If the admin/guardian does not pause the operator in time,
                    the attacker drains user funds from the vault. The exploit
                    assumes the project fails to act during the warning window.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "25. oos-prerequisite-root-cause-missing",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn("In-Scope Trigger / Root Cause", proc.stdout)

    def test_high_theft_with_non_privileged_root_cause_passes_check25(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "non_privileged_root_cause.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Vault accounting bug lets attacker steal user funds

                    **Severity:** High

                    **Rubric:** Direct theft of any user funds.
                    **Dollar impact:** $500,000 of user funds.

                    ## Impact

                    The attacker drains user funds from the vault.

                    ## In-Scope Trigger / Root Cause

                    The root cause is an in-scope source-level contract bug.
                    A non-privileged attacker can call `withdraw()` twice in one
                    transaction because the contract updates accounting after
                    the external transfer. The exploit does not rely on admin,
                    guardian, operator, private-key, prover, or off-chain
                    infrastructure compromise.
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "25. OOS prerequisite gate: pass",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("25. oos-prerequisite-root-cause-missing", proc.stdout)


if __name__ == "__main__":
    unittest.main()
