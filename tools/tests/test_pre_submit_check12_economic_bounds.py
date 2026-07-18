#!/usr/bin/env python3
"""Regression coverage for pre-submit Check 12 economic bounds.

POLY-45 was a Low-severity Polymarket filing rejected as unrealistic bounds:
the reported uint248 packing overflow required makerAmount >= 2^248, which
could not be reached under production token supply/caps. Check 12 must hard
fail that class for every reportable severity unless the draft gives a positive
production-reachable bound calculation.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _make_draft(tmp: Path, body: str) -> Path:
    ws = tmp / "audits" / "demo"
    draft_dir = ws / "submissions" / "paste_ready"
    draft_dir.mkdir(parents=True)
    draft = draft_dir / "candidate.md"
    draft.write_text(
        textwrap.dedent(
            f"""
            # Uint248 packing overflow in Exchange allows replay

            **Severity:** Low
            **Rubric:** Missing input validation that does not lead to fund loss.
            **Dollar impact:** $1,000.
            **Originality:** prior audit grep run completed.
            **In-scope:** production exchange accounting path.

            ## Impact

            {body}

            ## Proof of Concept

            `test/OrderStatusOverflowPoC.t.sol` demonstrates the arithmetic.
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    return draft


def _run(draft: Path, tmp: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(tmp / "audits")
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Low"],
        capture_output=True,
        text=True,
        env=env,
    )


class PreSubmitCheck12EconomicBoundsTests(unittest.TestCase):
    def test_poly45_self_admitted_unreachable_bound_hard_fails_low(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            draft = _make_draft(
                tmp,
                """
                The replay requires makerAmount >= 2^248. This is unreachable
                with any realistic ERC20 supply, practical exploitability is
                effectively zero, and the path is self-harm only because no
                third-party funds are at risk.
                """,
            )

            proc = _run(draft, tmp)

            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertIn(
                "12. economic-non-viable extreme-value claim",
                proc.stdout,
                proc.stdout,
            )

    def test_extreme_bound_without_reachable_max_hard_fails_low(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            draft = _make_draft(
                tmp,
                """
                The order can be replayed when remaining_after_decrement is
                exactly 2^248, causing the packed slot to zero and reset.
                """,
            )

            proc = _run(draft, tmp)

            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            self.assertIn(
                "12. Extreme value (>=2^248 or type(uintN).max) cited without "
                "realistic-bounds justification",
                proc.stdout.replace("≥", ">="),
                proc.stdout,
            )

    def test_extreme_bound_with_positive_reachable_bound_passes_check12(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            draft = _make_draft(
                tmp,
                """
                The trigger is 2^248. Given token supply is 2^250 in the
                production asset and the per-order cap is also above 2^248,
                this amount is realistically achievable because the signed
                maker balance and allowance can both exceed the threshold.
                """,
            )

            proc = _run(draft, tmp)

            self.assertIn(
                "12. Extreme value claim has realistic-bounds justification",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn(
                "12. economic-non-viable extreme-value claim",
                proc.stdout,
                proc.stdout,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
