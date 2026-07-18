#!/usr/bin/env python3
"""MQ-C02 operand-commensurability-screen - non-vacuous regression.

Pins tools/operand-commensurability-screen.py: for a comparison / sum / subtraction
that TRUSTS its two operands to be commensurable, it flags (verdict="needs-fuzz")
when the two operands are proven to be in DIFFERENT accounting bases - vault SHARES
vs underlying ASSETS, ray-index-SCALED vs RAW principal, pre-fee GROSS vs post-fee
NET, an external rebasing balanceOf() vs a static internal balance.

Non-vacuity is enforced (HARD RULE 6):
  (1) PLANTED POSITIVES fire on ALL FOUR axes (SHARE / SCALE / FEE / REBASE) - a
      general invariant class, not one hard-coded shape.
  (2) CONSISTENT-basis negatives are silent - the same relation with BOTH operands
      in one basis (both shares; a `convertToAssets(shares)` making it commensurable;
      a `scaledTotalSupply.rayMul(index)` conversion) does NOT fire.
  (3) NEUTRALIZE each core-predicate half -> the positive assertion FAILS:
      (a) monkeypatching `_basis` to always-empty makes every positive go silent
          (the basis-inference half is load-bearing); and
      (b) monkeypatching `_divergences` to always-[] makes every positive go silent
          (the divergence-join half is load-bearing); and
      (c) making the two operands the SAME basis keeps the ROW but drops the fire
          (proves it is a divergence class, not a comparison shape).
  (4) FALSE-POSITIVE guards seen on the real fleet stay silent: a call-arg name
      (`maxWithdraw(isSharesLockup)` returns assets), a ratio (`assets.rDivUp(shares)`
      is a price), a numeric literal operand, a comment / string basis word.

The advisory-first contract (verdict=needs-fuzz, advisory=True, auto_credit=False,
default exit 0, --strict exit 1) and the .auditooor sidecar emission (firing
hypotheses only) are pinned too.

REAL-FLEET mutation-verify (HARD RULE 5) is reproduced end-to-end against the ACTUAL
fleet Solidity when present, WITHOUT mutating any ws file: the tool is SILENT on the
real consistent source (aave-v3 ValidationLogic.validateSupply, where a
`.rayMul(index)` converts the scaled supply to raw BEFORE the supply-cap compare),
and FIRES on an in-memory TEMP COPY whose `.rayMul(index)` conversion is stripped
(scaled-vs-raw divergence). It SKIPs if the source is absent (no faked pass).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "operand_commensurability_screen_t",
        TOOLS / "operand-commensurability-screen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load_tool()


def _rows(text, name="T.sol"):
    return MOD.scan_file(pathlib.Path(name), name, file_text=text)


def _fired(text, fn):
    return [r for r in _rows(text) if r["fires"] and r["function"] == fn]


# ---------------------------------------------------------------------------
# Planted positives - one per accounting axis (a basis divergence).
# ---------------------------------------------------------------------------
SHARE_POS = ('contract C{function f(uint256 userShares,uint256 totalAssets)'
             ' external{require(userShares<=totalAssets,"x");}}')
SHARE_CONV_POS = ('contract C{function f(uint256 amt,uint256 userShares)'
                  ' external{require(convertToAssets(amt)<=userShares,"x");}}')
SCALE_POS = ('contract C{function f(uint256 amount) external view'
             '{require(scaledTotalSupply+amount<=supplyCap*(10**18),"x");}}')
FEE_POS = ('contract C{function f(uint256 grossAmount,uint256 netAmount)'
           ' external{require(grossAmount<=netAmount,"x");}}')
REBASE_POS = ('contract C{function f() external'
              '{require(token.balanceOf(address(this))>=internalBalance,"x");}}')


class TestPlantedPositivesFireOnEveryAxis(unittest.TestCase):
    def test_share_axis_fires(self):
        fr = _fired(SHARE_POS, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "SHARE")
        self.assertEqual(fr[0]["left_basis"]["SHARE"], "shares")
        self.assertEqual(fr[0]["right_basis"]["SHARE"], "assets")
        self.assertEqual(fr[0]["capability"], "MQ-C02-operand-commensurability")
        self.assertEqual(fr[0]["lang"], "solidity")

    def test_share_via_conversion_provenance_fires(self):
        # convertToAssets(amt) is authoritatively ASSETS; compared to shares -> fire.
        fr = _fired(SHARE_CONV_POS, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "SHARE")
        self.assertEqual(fr[0]["left_basis"]["SHARE"], "assets")

    def test_scale_axis_fires(self):
        # an unconverted scaled supply compared to a raw (10**dec) cap -> fire.
        fr = _fired(SCALE_POS, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "SCALE")
        self.assertEqual(fr[0]["left_basis"]["SCALE"], "scaled")
        self.assertEqual(fr[0]["right_basis"]["SCALE"], "raw")

    def test_fee_axis_fires(self):
        fr = _fired(FEE_POS, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "FEE")

    def test_rebase_axis_fires(self):
        fr = _fired(REBASE_POS, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "REBASE")
        self.assertEqual(fr[0]["left_basis"]["REBASE"], "rebasing")
        self.assertEqual(fr[0]["right_basis"]["REBASE"], "static")


# ---------------------------------------------------------------------------
# Consistent-basis negatives - the SAME relation with commensurable operands.
# ---------------------------------------------------------------------------
class TestConsistentBasisSilent(unittest.TestCase):
    def test_same_basis_shares_silent(self):
        src = ('contract C{function f(uint256 userShares,uint256 maxShares)'
               ' external{require(userShares<=maxShares,"x");}}')
        self.assertEqual(_fired(src, "f"), [])

    def test_conversion_makes_it_commensurable_silent(self):
        # convertToAssets(shares) is assets; compared to an asset cap -> consistent.
        src = ('contract C{function f(uint256 shares,uint256 assetCap)'
               ' external{require(convertToAssets(shares)<=assetCap,"x");}}')
        self.assertEqual(_fired(src, "f"), [])

    def test_raymul_conversion_makes_scale_commensurable_silent(self):
        # scaledTotalSupply.rayMul(index) is RAW; compared to a raw cap -> consistent.
        src = ('contract C{function f(uint256 amount) external view'
               '{require(scaledTotalSupply.rayMul(index)+amount<=supplyCap*(10**18),"x");}}')
        self.assertEqual(_fired(src, "f"), [])


# ---------------------------------------------------------------------------
# Neutralize each core-predicate half -> the positive must FAIL.
# ---------------------------------------------------------------------------
class TestNeutralizeCorePredicate(unittest.TestCase):
    def test_neutralize_basis_inference_kills_all_fires(self):
        orig = MOD._basis
        try:
            MOD._basis = lambda text, body: {}
            for src in (SHARE_POS, SCALE_POS, FEE_POS, REBASE_POS):
                self.assertEqual(_fired(src, "f"), [],
                                 "basis inference must be load-bearing")
        finally:
            MOD._basis = orig

    def test_neutralize_divergence_join_kills_all_fires(self):
        orig = MOD._divergences
        try:
            MOD._divergences = lambda lb, rb: []
            for src in (SHARE_POS, SCALE_POS, FEE_POS, REBASE_POS):
                self.assertEqual(_fired(src, "f"), [],
                                 "divergence-join must be load-bearing")
        finally:
            MOD._divergences = orig

    def test_same_basis_keeps_row_but_drops_fire(self):
        # Force both operands to the SAME basis -> the ROW survives (it is still a
        # candidate comparison) but does NOT fire -> proves this is a divergence
        # CLASS, not a comparison shape.
        same = ('contract C{function f(uint256 userShares,uint256 maxShares)'
                ' external{require(userShares<=maxShares,"x");}}')
        rows = [r for r in _rows(same) if r["function"] == "f"]
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"])
        self.assertEqual(rows[0]["divergences"], [])


# ---------------------------------------------------------------------------
# False-positive guards - regressions for classes seen on the real fleet.
# ---------------------------------------------------------------------------
class TestFalsePositiveGuards(unittest.TestCase):
    def test_ratio_operand_is_ambiguous_silent(self):
        # `assets.rDivUp(shares)` is a PRICE (assets/shares), not assets; carrying
        # BOTH tokens -> ambiguous -> silent. (real: morpho GeneralAdapter1)
        src = ('contract C{function f(uint256 assets,uint256 shares)'
               ' external{require(assets.rDivUp(shares)<=maxSharePriceE27,"x");}}')
        self.assertEqual(_fired(src, "f"), [])

    def test_call_arg_name_does_not_set_basis_silent(self):
        # `maxWithdraw(isSharesLockup)` returns assets; the `shares` in the ARG is
        # noise and must NOT label the operand. (real: strata StrataCDO)
        src = ('contract C{function f(uint256 baseAssets)'
               ' external{require(baseAssets>pool.maxWithdraw(isSharesLockup),"x");}}')
        self.assertEqual(_fired(src, "f"), [])

    def test_numeric_literal_operand_drops_row(self):
        src = ('contract C{function f(uint256 userShares)'
               ' external{require(userShares<=1000,"x");}}')
        self.assertEqual([r for r in _rows(src) if r["function"] == "f"], [])

    def test_comment_and_string_basis_words_are_masked(self):
        # a basis word inside a comment / string must not create a token.
        src = ('contract C{function f(uint256 a,uint256 b) external{'
               '// compare shares vs assets here\n'
               'string memory note="shares and assets";'
               'require(a<=b,"x");}}')
        self.assertEqual(_fired(src, "f"), [])


# ---------------------------------------------------------------------------
# Deliberate cross-basis PRICE / RATE bound - a share-price sanity check whose
# revert reason / selector signals intent must stay SILENT (not a units mismatch).
# ---------------------------------------------------------------------------
class TestPriceRateBoundSuppression(unittest.TestCase):
    def test_shareprice_error_selector_suppresses(self):
        # real morpho FP: `require(mintedShares >= assets, SharePriceAboveOne())`
        # asserts share-price>=1 - the shares-vs-assets ORDERING is the intended
        # invariant, not an accidental units mismatch -> SILENT.
        src = ('contract C{function f(uint256 mintedShares,uint256 assets)'
               ' external{require(mintedShares>=assets,SharePriceAboveOne());}}')
        rows = [r for r in _rows(src) if r["function"] == "f"]
        self.assertEqual(len(rows), 1, rows)
        # the divergence is still COMPUTED (row kept) but the fire is suppressed.
        self.assertEqual(rows[0]["axis"], "SHARE")
        self.assertTrue(rows[0]["divergences"])
        self.assertFalse(rows[0]["fires"])
        self.assertTrue(rows[0]["suppressed_price_rate_bound"])
        self.assertEqual(_fired(src, "f"), [])

    def test_string_revert_reason_suppresses(self):
        # a STRING revert reason (masked from the token view) still signals intent -
        # it must be read from the comments-stripped-strings-kept view -> SILENT.
        src = ('contract C{function f(uint256 mintedShares,uint256 assets)'
               ' external{require(mintedShares>=assets,"share price above one");}}')
        self.assertEqual(_fired(src, "f"), [])

    def test_rate_and_peg_and_bound_selectors_suppress(self):
        for sel in ("ExchangeRateOutOfBand", "PegDeviation", "PriceBoundExceeded",
                    "RateBelowMin"):
            src = ('contract C{function f(uint256 userShares,uint256 totalAssets)'
                   ' external{require(userShares<=totalAssets,' + sel + '());}}')
            self.assertEqual(_fired(src, "f"), [], sel)

    def test_genuine_mismatch_with_nonprice_selector_still_fires(self):
        # a genuine accidental shares-vs-assets divergence whose selector does NOT
        # signal a price/rate bound MUST still fire (suppression is narrow).
        src = ('contract C{function f(uint256 userShares,uint256 totalAssets)'
               ' external{require(userShares<=totalAssets,InsufficientBalance());}}')
        fr = _fired(src, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "SHARE")
        self.assertFalse(fr[0]["suppressed_price_rate_bound"])

    def test_genuine_mismatch_with_plain_string_still_fires(self):
        # SHARE_POS uses a `"x"` reason - no price/rate word -> still fires.
        self.assertEqual(len(_fired(SHARE_POS, "f")), 1)

    def test_comment_mentioning_price_does_not_suppress(self):
        # a COMMENT is not an assertion of intent: a genuine mismatch whose only
        # 'price'/'rate' token lives in a comment MUST still fire.
        src = ('contract C{function f(uint256 userShares,uint256 totalAssets)'
               ' external{\n// this compares a share-price rate somewhere\n'
               'require(userShares<=totalAssets,InsufficientBalance());}}')
        fr = _fired(src, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertFalse(fr[0]["suppressed_price_rate_bound"])


# ---------------------------------------------------------------------------
# Arithmetic (sum / subtraction) sites, not only comparisons.
# ---------------------------------------------------------------------------
class TestArithmeticSites(unittest.TestCase):
    def test_subtraction_of_divergent_bases_fires(self):
        # a value-conservation `out = grossAmount - netFee` mixes gross and net.
        src = ('contract C{function f(uint256 grossAmount,uint256 netFee)'
               ' external{uint256 out=grossAmount-netFee;emit E(out);}}')
        fr = _fired(src, "f")
        self.assertEqual(len(fr), 1, fr)
        self.assertEqual(fr[0]["axis"], "FEE")
        self.assertEqual(fr[0]["kind"], "arithmetic")


# ---------------------------------------------------------------------------
# Advisory-first contract + sidecar emission + exit codes.
# ---------------------------------------------------------------------------
class TestAdvisoryContractAndSidecar(unittest.TestCase):
    def test_rows_are_advisory_needs_fuzz(self):
        r = _fired(SHARE_POS, "f")[0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])
        for k in ("file", "line", "function", "capability"):
            self.assertIn(k, r)

    def test_workspace_emits_sidecar_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "Share.sol").write_text(SHARE_POS)
            (src / "Scale.sol").write_text(SCALE_POS)
            (src / "Ok.sol").write_text(
                'contract C{function f(uint256 userShares,uint256 maxShares)'
                ' external{require(userShares<=maxShares,"x");}}')
            # default (advisory) -> exit 0 even though divergences exist
            self.assertEqual(MOD.main(["--workspace", str(ws)]), 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            self.assertTrue(side.exists(), "sidecar must be emitted under .auditooor/")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertGreaterEqual(len(rows), 2)
            for r in rows:
                self.assertTrue(r["fires"])
                self.assertEqual(r["capability"], "MQ-C02-operand-commensurability")
                self.assertEqual(r["verdict"], "needs-fuzz")
                self.assertIn("line", r)
                self.assertIn("function", r)
            # the consistent-basis file must NOT appear among the firing rows
            self.assertFalse(any("Ok.sol" in r["file"] for r in rows))
            # --strict -> exit 1 when a divergence fired
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 1)
            # --check re-reads the sidecar (advisory), default exit 0
            self.assertEqual(MOD.main(["--workspace", str(ws), "--check"]), 0)

    def test_clean_workspace_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "src").mkdir()
            (ws / "src" / "Ok.sol").write_text(
                'contract C{function f(uint256 userShares,uint256 maxShares)'
                ' external{require(userShares<=maxShares,"x");}}')
            self.assertEqual(MOD.main(["--workspace", str(ws), "--strict"]), 0)


# ---------------------------------------------------------------------------
# HARD RULE 5 - real-fleet mutation-verify (read-only; temp copy in memory).
# ---------------------------------------------------------------------------
class TestRealFleetMutationVerify(unittest.TestCase):
    ANCHOR = pathlib.Path(
        "/Users/wolf/audits/lido/src/aave-delivery-infrastructure/lib/"
        "aave-address-book/lib/aave-v3-core/contracts/protocol/libraries/"
        "logic/ValidationLogic.sol")

    def test_validate_supply_raymul_consistent_silent_then_fires(self):
        if not self.ANCHOR.exists():
            self.skipTest("aave-v3 ValidationLogic fleet source not present")
        real = self.ANCHOR.read_text(encoding="utf-8", errors="ignore")
        rows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=real)
                if r["function"] == "validateSupply"]
        # the real source is CONSISTENT: the scaled supply is rayMul(index)-converted
        # to raw BEFORE the supply-cap compare -> NO row in validateSupply fires.
        self.assertTrue(rows, "validateSupply must yield candidate rows")
        self.assertFalse(any(r["fires"] for r in rows),
                         "the real rayMul-converted compare must be SILENT")
        # TEMP COPY with the `.rayMul(reserveCache.nextLiquidityIndex)` conversion
        # stripped -> the scaled supply is now compared RAW-vs-scaled -> must FIRE.
        mutated = re.sub(r"\)\.rayMul\(reserveCache\.nextLiquidityIndex\)", ")", real)
        self.assertNotEqual(mutated, real, "mutation must actually strip the rayMul")
        mrows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=mutated)
                 if r["function"] == "validateSupply" and r["fires"]]
        self.assertEqual(len(mrows), 1, mrows)
        self.assertEqual(mrows[0]["axis"], "SCALE")
        self.assertEqual(mrows[0]["left_basis"]["SCALE"], "scaled")
        self.assertEqual(mrows[0]["right_basis"]["SCALE"], "raw")


# ---------------------------------------------------------------------------
# Real-fleet read-only (morpho): the deliberate SharePriceAboveOne bound is SILENT
# on the actual source; a temp copy that renames the selector to a non-price error
# FIRES (proving the suppression is what silences it, not some other guard).
# ---------------------------------------------------------------------------
class TestRealFleetMorphoSharePriceSuppression(unittest.TestCase):
    ANCHOR = pathlib.Path(
        "/Users/wolf/audits/morpho/src/vault-v2-marketadapter/src/adapters/"
        "MorphoMarketV1AdapterV2.sol")

    def test_morpho_shareprice_bound_silent_then_fires_when_renamed(self):
        if not self.ANCHOR.exists():
            self.skipTest("morpho MorphoMarketV1AdapterV2 fleet source not present")
        real = self.ANCHOR.read_text(encoding="utf-8", errors="ignore")
        rows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=real)
                if r["line"] == 190]
        # the deliberate `require(mintedShares >= assets, SharePriceAboveOne())` is a
        # cross-basis share-price bound -> row kept, divergence computed, NO fire.
        self.assertTrue(rows, "line 190 must yield a candidate row")
        self.assertTrue(any(r["divergences"] for r in rows))
        self.assertFalse(any(r["fires"] for r in rows),
                         "the deliberate SharePriceAboveOne bound must be SILENT")
        self.assertTrue(any(r.get("suppressed_price_rate_bound") for r in rows))
        # whole-file: zero fires (this was the single fleet FP).
        self.assertEqual(
            [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=real)
             if r["fires"]], [])
        # TEMP COPY: rename the price-signalling selector to a neutral one -> the same
        # shares-vs-assets ordering now reads as a genuine mismatch -> must FIRE.
        mutated = real.replace("SharePriceAboveOne", "InsufficientBalance")
        self.assertNotEqual(mutated, real, "mutation must rename the selector")
        mrows = [r for r in MOD.scan_file(self.ANCHOR, self.ANCHOR.name, file_text=mutated)
                 if r["line"] == 190 and r["fires"]]
        self.assertEqual(len(mrows), 1, mrows)
        self.assertEqual(mrows[0]["axis"], "SHARE")


if __name__ == "__main__":
    unittest.main()
