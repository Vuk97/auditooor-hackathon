#!/usr/bin/env python3
"""Regression (Strata 2026-07-07): hunt-coverage-gate must exempt bodyless Solidity
interface declarations from the COVERAGE DENOMINATOR, not only from queued_not_scanned.

Interface methods that were never queued land in `unlogged_uncovered` (not
queued_not_scanned), so the pre-existing sol_interface_exempt (which only prunes
queued_not_scanned) never reached them. On Strata 97/100 unlogged-uncovered units were
IAccounting/IAprPairFeed/ICooldown interface method decls, pinning the token-coverage
fraction at 78.72% forever (a permanent false-red - an interface method has no body to
hunt). The denom-level exemption removes ONLY positively-bodyless declarations; an
implemented function keeps its coverage obligation (never-false-pass)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hunt-coverage-gate.py"


class DenomInterfaceExemptTest(unittest.TestCase):
    def _run(self, ws: Path) -> dict:
        r = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws), "--json"],
            capture_output=True, text=True, timeout=180,
        )
        return json.loads(r.stdout)

    def test_interface_decls_excluded_from_denominator(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            src = ws / "src"
            src.mkdir(parents=True)
            # A pure interface: 3 bodyless method decls -> must NOT count against coverage.
            (src / "IThing.sol").write_text(
                "pragma solidity ^0.8.0;\n"
                "interface IThing {\n"
                "  function a() external returns (bool);\n"
                "  function b(uint256 x) external view returns (uint256);\n"
                "  function c(address who) external;\n"
                "}\n"
            )
            # An implemented contract fn -> stays an obligation (never exempt).
            (src / "Impl.sol").write_text(
                "pragma solidity ^0.8.0;\n"
                "contract Impl {\n"
                "  function doWork(uint256 x) external returns (uint256) { return x + 1; }\n"
                "}\n"
            )
            d = self._run(ws)
            exempt = d.get("denom_interface_exempt_units") or []
            # all three interface methods exempted from the denominator
            self.assertGreaterEqual(d.get("denom_interface_exempt_count", 0), 3, d.get("verdict"))
            self.assertTrue(any("IThing.sol::a" in u for u in exempt))
            self.assertTrue(any("IThing.sol::b" in u for u in exempt))
            # the implemented function is NEVER interface-exempted (never-false-pass)
            self.assertFalse(any("Impl.sol::doWork" in u for u in exempt))

    def test_implemented_only_workspace_exempts_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            ws = Path(t)
            src = ws / "src"
            src.mkdir(parents=True)
            (src / "Only.sol").write_text(
                "pragma solidity ^0.8.0;\n"
                "contract Only {\n"
                "  function f() external returns (bool) { return true; }\n"
                "  function g() external returns (bool) { return false; }\n"
                "}\n"
            )
            d = self._run(ws)
            # no bodyless decls -> denom exemption must be empty (cannot hide real fns)
            self.assertEqual(d.get("denom_interface_exempt_count", 0), 0)


if __name__ == "__main__":
    unittest.main()
