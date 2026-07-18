#!/usr/bin/env python3
"""Lock test for P-13 validator_lacks_ancestry_walk.

Source: Base-Azul engagement-3 FN-5 (AnchorStateRegistry.sol:314-336,
``isGameClaimValid``). The validator reads a single ``.parent()`` and
returns a bool, while callers treat the bool as "entire ancestry is
valid". A malicious leaf whose immediate parent is valid but whose
grandparent is invalid slips through.

Hard-negative: a counter-fixture that describes a walk-up loop over the
ancestor chain must NOT be flagged.
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


class P13ValidatorLacksAncestryWalkTests(unittest.TestCase):
    def test_positive_fixture_flags_single_level_parent_validator(self) -> None:
        """AnchorStateRegistry.isGameClaimValid shape — must flag."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                "# Scope\n\nIn scope: dispute-game ancestry validation.\n"
            )

            draft = ws / "fn5.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    ## Finding: isGameClaimValid reads only the immediate parent

                    AnchorStateRegistry.isGameClaimValid(game) reads only the immediate parent status and returns a bool.
                    The validator walks no ancestor chain, so a malicious leaf whose parent is valid
                    but whose grandparent is invalid slips through.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertIn("validator_lacks_ancestry_walk", names, out)
            flag = next(
                f
                for f in out["flags"]
                if f["pattern_name"] == "validator_lacks_ancestry_walk"
            )
            self.assertEqual(flag["declared_severity"], "MEDIUM")
            self.assertEqual(flag["severity"], "advisory")
            self.assertGreater(len(flag["matches_found"]), 0)

    def test_negative_fixture_with_walk_loop_stays_clean(self) -> None:
        """Counter-fixture: validator documents a walk-up loop over ancestors."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scope = ws / "SCOPE.md"
            scope.write_text(
                "# Scope\n\nIn scope: dispute-game ancestry validation.\n"
            )

            counter = ws / "fn5_counter.md"
            counter.write_text(
                textwrap.dedent(
                    """
                    ## Finding: isGameClaimValid walks the full ancestry

                    isGameClaimValid(game) performs a while-loop from the leaf up
                    to the anchor root. At each step it reads the node status and
                    aborts on the first invalid ancestor, so a malicious leaf
                    cannot pass validation even when its direct parent is valid.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(counter, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertNotIn("validator_lacks_ancestry_walk", names, out)

    def test_hard_negative_unrelated_overflow_draft_stays_clean(self) -> None:
        """Hard-negative: integer-overflow draft must not trip P-13."""
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
                    exceeds 2**256. Fix: use Solidity 0.8+ checked arithmetic.
                    """
                ).strip()
                + "\n"
            )

            out = _run_tool(draft, scope=scope)
            names = [f["pattern_name"] for f in out["flags"]]
            self.assertNotIn("validator_lacks_ancestry_walk", names, out)


if __name__ == "__main__":
    unittest.main()
