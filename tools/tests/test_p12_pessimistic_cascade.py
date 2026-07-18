#!/usr/bin/env python3
"""Lock test for P-12 pessimistic_cascade_ignores_recipient_reassignment.

Source: Base-Azul engagement-3 FN-1 (AggregateVerifier.resolve, invalid-parent
branch at AggregateVerifier.sol:447-467 of the Cantina M-1 fix). The patched
pessimistic branch writes ``status = INVALID`` but forgets the sibling write
to ``recipient = challenger`` that the else-branch performs, leaving the
pre-existing ``recipient`` (the original claimant) live to collect refunds.

Hard-negative: a counter-fixture explicitly describing ``recipient = challenger``
in the pessimistic branch must NOT be flagged. This keeps the regex from
devolving into "any paragraph that mentions pessimistic + recipient".
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scope-reasoner.py"


def _run_tool(draft: Path, scope: Path | None = None) -> dict:
    cmd = [sys.executable, str(TOOL), "--draft", str(draft)]
    if scope is not None:
        cmd += ["--scope", str(scope)]
    proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(proc.stdout)


class P12PessimisticCascadeTests(unittest.TestCase):
    def test_positive_fixture_flags_recipient_reassignment_gap(self) -> None:
        """AggregateVerifier.resolve invalid-parent branch shape — must flag."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                "# Scope\n\nIn scope: aggregate verifier resolution state.\n"
            )

            draft = ws / "fn1.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: pessimistic resolve forgets recipient reassignment

                    In AggregateVerifier.resolve the invalid-parent branch sets
                    status = INVALID without a matching update to recipient.
                    The sibling else-branch reassigns recipient = challenger
                    but the pessimistic path skips that write, so the stale
                    recipient from the pre-resolution state remains and will
                    receive the bond refund.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn(
                "pessimistic_cascade_ignores_recipient_reassignment", names, out
            )
            flag = next(
                f
                for f in out["flags"]
                if f["pattern_name"]
                == "pessimistic_cascade_ignores_recipient_reassignment"
            )
            self.assertEqual(flag["declared_severity"], "MEDIUM")
            self.assertEqual(flag["severity"], "advisory")
            self.assertGreater(len(flag["matches_found"]), 0)

    def test_negative_fixture_branch_rewrites_recipient_stays_clean(self) -> None:
        """Counter-fixture: pessimistic branch explicitly reassigns recipient."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                "# Scope\n\nIn scope: aggregate verifier resolution state.\n"
            )

            counter = ws / "fn1_counter.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: pessimistic resolve correctly reassigns recipient

                    In AggregateVerifier.resolve the invalid-parent branch sets
                    status = INVALID and also writes recipient = challenger
                    before returning. Both the pessimistic and the optimistic
                    else-branch perform the parallel recipient update so the
                    challenger receives the bond in every resolved branch.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(counter, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertNotIn(
                "pessimistic_cascade_ignores_recipient_reassignment", names, out
            )

    def test_hard_negative_unrelated_overflow_draft_stays_clean(self) -> None:
        """Hard-negative: integer-overflow draft with none of the status /
        recipient vocabulary must not accidentally trip P-12."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text("# Scope\n\nIn scope: ERC-20 token contract.\n")

            draft = ws / "overflow.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: integer overflow in transfer

                    The transfer function permits overflow when amount + balance
                    exceeds 2**256, corrupting the sender balance. Fix: use
                    SafeMath or Solidity 0.8+ checked arithmetic.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertNotIn(
                "pessimistic_cascade_ignores_recipient_reassignment", names, out
            )


if __name__ == "__main__":
    unittest.main()
