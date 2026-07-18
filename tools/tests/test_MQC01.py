#!/usr/bin/env python3
"""MQ-C01 rounding-direction-consistency screen - non-vacuous regression.

Pins tools/rounding-direction-consistency-screen.py: on a value-conservation
path it flags a SHARES conversion whose rounding is attacker-favorable - a shares
CREDIT (minted on deposit/mint, debt reduced on repay) rounded UP, or a shares
DEBIT (burned on withdraw/redeem, debt created on borrow) rounded DOWN. Every row
is advisory verdict="needs-fuzz".

Non-vacuity (all three legs REQUIRED by the build spec):
  (1) PLANTED POSITIVE fires  - a deposit that mints shares rounded UP flags; a
      withdraw that burns shares rounded DOWN flags.
  (2) PROVEN-CONSISTENT NEGATIVE silent - the canonical Morpho directions
      (deposit->toSharesDown, withdraw->toSharesUp, borrow->toSharesUp,
      repay->toSharesDown) do NOT flag.
  (3) NEUTRALIZE the core predicate - monkeypatch `_classify_site` so nothing is
      ever favorable-mismatched; the planted positive must then STOP firing,
      proving the direction predicate is load-bearing, not decoration.
Plus precision regressions drawn from the REAL fleet false positives that the
screen must stay SILENT on: an assets-basis valuation (strata convertToAssets
Floor), a verb-substring view helper (expectedSupplyAssets), a rounding carried
in a variable (OZ _convertToShares(assets, rounding)), and a lone `/` scale op.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
TOOL = TOOLS / "rounding-direction-consistency-screen.py"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load():
    spec = importlib.util.spec_from_file_location(
        "rounding_direction_consistency_screen_t", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MQ = _load()


def _rows(src: str, rel: str = "T.sol"):
    return MQ.scan_file(pathlib.Path(rel), rel, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --- planted positives ------------------------------------------------------
# deposit mints shares to the caller (a CREDIT); rounding UP hands the caller
# more shares than the assets deposited justify -> attacker-favorable -> FIRES.
SOL_DEPOSIT_CREDIT_UP = """
contract Vault {
    function deposit(uint256 assets) external returns (uint256 shares) {
        shares = assets.mulDivUp(totalShares, totalAssets);   // credit rounded UP
        _mint(msg.sender, shares);
    }
}
"""

# withdraw burns the caller's shares (a DEBIT); rounding DOWN burns fewer shares
# than the assets withdrawn require -> attacker-favorable -> FIRES.
SOL_WITHDRAW_DEBIT_DOWN = """
contract Vault {
    function withdraw(uint256 assets) external returns (uint256 shares) {
        shares = assets.mulDivDown(totalShares, totalAssets); // debit rounded DOWN
        _burn(msg.sender, shares);
    }
}
"""

# OZ-style: previewMint pays cost in shares? No - the SHARES-basis firing case
# with an explicit Rounding literal: a repay that credits (reduces) debt shares
# but rounds them UP (caller over-credited on debt reduction) -> FIRES.
SOL_REPAY_ROUNDING_CEIL = """
contract Lender {
    function repay(uint256 assets) external returns (uint256 shares) {
        shares = _convertToShares(assets, Math.Rounding.Ceil); // repay credit UP
    }
}
"""

# --- proven-consistent negatives (the canonical Morpho directions) ----------
SOL_MORPHO_CONSISTENT = """
contract Morpho {
    function supply(uint256 assets) external returns (uint256 shares) {
        shares = assets.toSharesDown(totalSupplyAssets, totalSupplyShares);
    }
    function withdraw(uint256 assets) external returns (uint256 shares) {
        shares = assets.toSharesUp(totalSupplyAssets, totalSupplyShares);
    }
    function borrow(uint256 assets) external returns (uint256 shares) {
        shares = assets.toSharesUp(totalBorrowAssets, totalBorrowShares);
    }
    function repay(uint256 assets) external returns (uint256 shares) {
        shares = assets.toSharesDown(totalBorrowAssets, totalBorrowShares);
    }
}
"""

# --- fleet-observed precision regressions (must stay SILENT) ----------------
# (a) assets-basis input valuation: strata previewDeposit converts a meta-token
#     to base assets with Floor - protocol-favorable, NOT a debit-should-be-up.
SOL_ASSETS_BASIS_VALUATION = """
contract Tranche {
    function previewDeposit(address token, uint256 tokenAmount) public view returns (uint256) {
        uint256 baseAssets = strategy.convertToAssets(token, tokenAmount, Math.Rounding.Floor);
        return baseAssets;
    }
}
"""

# (b) verb-substring VIEW helper: a name that merely CONTAINS "supply" is not the
#     supply operation - its shares/assets rounding is a valuation, stay silent.
SOL_VERB_SUBSTRING_VIEW = """
contract Lib {
    function expectedSupplyAssets(uint256 shares) internal view returns (uint256) {
        return shares.toAssetsDown(totalSupplyAssets, totalSupplyShares);
    }
    function _accruedSupplyBalance(uint256 shares) internal view returns (uint256) {
        return shares.mulDivDown(totalSupplyAssets, totalSupplyShares);
    }
}
"""

# (c) rounding carried in a VARIABLE (OZ _convertToShares(assets, rounding)): the
#     direction is decided by the caller, unknown at this site -> silent.
SOL_ROUNDING_VAR = """
contract V {
    function deposit(uint256 assets, Math.Rounding rounding) internal returns (uint256 shares) {
        shares = assets.mulDiv(totalShares, totalAssets, rounding);
    }
}
"""

# (d) a lone `/` scale op with no multiply - not a value conversion -> silent.
SOL_LONE_DIV = """
contract Beacon {
    function deposit(uint256 amount) external returns (uint256 shares) {
        shares = amount / 1 gwei;   // scale, not a share conversion
    }
}
"""


class TestPositivesFire(unittest.TestCase):
    def test_deposit_credit_rounded_up_fires(self):
        fired = _fired(_rows(SOL_DEPOSIT_CREDIT_UP))
        self.assertTrue(fired, "a shares CREDIT rounded UP on deposit must fire")
        r = fired[0]
        self.assertEqual(r["verb"], "deposit")
        self.assertEqual(r["basis"], "shares")
        self.assertEqual(r["sink_kind"], "credit")
        self.assertEqual(r["rounding"], "up")
        self.assertEqual(r["expected_rounding"], "down")

    def test_withdraw_debit_rounded_down_fires(self):
        fired = _fired(_rows(SOL_WITHDRAW_DEBIT_DOWN))
        self.assertTrue(fired, "a shares DEBIT rounded DOWN on withdraw must fire")
        r = fired[0]
        self.assertEqual(r["sink_kind"], "debit")
        self.assertEqual(r["rounding"], "down")
        self.assertEqual(r["expected_rounding"], "up")

    def test_repay_credit_ceil_fires(self):
        fired = _fired(_rows(SOL_REPAY_ROUNDING_CEIL))
        self.assertTrue(any(r["function"] == "repay" for r in fired),
                        "a repay shares-credit rounded Ceil must fire")


class TestProvenConsistentSilent(unittest.TestCase):
    def test_canonical_morpho_directions_silent(self):
        rows = _rows(SOL_MORPHO_CONSISTENT)
        self.assertEqual(_fired(rows), [],
                         "the canonical Morpho rounding directions are "
                         "protocol-favorable and must be SILENT")


class TestFleetPrecisionRegressions(unittest.TestCase):
    def test_assets_basis_valuation_silent(self):
        self.assertEqual(_fired(_rows(SOL_ASSETS_BASIS_VALUATION)), [],
                         "an assets-basis input valuation must stay silent")

    def test_verb_substring_view_helper_silent(self):
        self.assertEqual(_fired(_rows(SOL_VERB_SUBSTRING_VIEW)), [],
                         "a name that merely contains a verb is not the op")

    def test_rounding_in_variable_silent(self):
        self.assertEqual(_fired(_rows(SOL_ROUNDING_VAR)), [],
                         "rounding carried in a variable is caller-decided")

    def test_lone_division_silent(self):
        self.assertEqual(_fired(_rows(SOL_LONE_DIV)), [],
                         "a lone `/` scale op is not a value conversion")


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing the favorability predicate makes the planted positive STOP
    firing -> the predicate is load-bearing (build-spec leg 3)."""

    def test_favorability_neutralized_kills_the_finding(self):
        orig = MQ._classify_site
        try:
            # force every site to be non-firing (rounding == expected)
            MQ._classify_site = lambda v, cs, b, r: ("credit", r, False)
            rows = _rows(SOL_DEPOSIT_CREDIT_UP)
            self.assertEqual(
                _fired(rows), [],
                "with the direction predicate neutralized the finding must "
                "vanish - proves it is load-bearing")
        finally:
            MQ._classify_site = orig

    def test_predicate_restored_fires_again(self):
        self.assertTrue(_fired(_rows(SOL_DEPOSIT_CREDIT_UP)),
                        "after restore the positive fires again (no leak)")


class TestAdvisoryContract(unittest.TestCase):
    def test_every_row_advisory_needs_fuzz(self):
        rows = _rows(SOL_DEPOSIT_CREDIT_UP)
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertTrue(r["advisory"])
            self.assertFalse(r["auto_credit"])
            self.assertEqual(r["capability"], "MQC01")
            for k in ("file", "line", "function", "verb", "basis"):
                self.assertIn(k, r)


class TestSidecarEmission(unittest.TestCase):
    """--workspace emits the needs-fuzz sidecar (mkdir parent) and stays exit 0
    (advisory-first); --strict raises the exit code."""

    def test_workspace_emits_sidecar_and_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            src = ws / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(SOL_DEPOSIT_CREDIT_UP)
            rc = subprocess.call(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(rc, 0, "advisory-first: default exit 0 even on fire")
            side = ws / ".auditooor" / \
                "rounding_direction_consistency_hypotheses.jsonl"
            self.assertTrue(side.exists(), "sidecar must be emitted")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertTrue(rows and rows[0]["fires"])
            self.assertEqual(rows[0]["capability"], "MQC01")
            self.assertIn("function", rows[0])
            # --strict raises the exit code when a mismatch exists
            rc_strict = subprocess.call(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--strict"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.assertEqual(rc_strict, 1, "--strict elevates exit on a fire")


if __name__ == "__main__":
    unittest.main()
