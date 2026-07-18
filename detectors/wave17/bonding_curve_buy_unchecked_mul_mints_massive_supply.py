"""
bonding-curve-buy-unchecked-mul-mints-massive-supply - generated from reference/patterns.dsl/bonding-curve-buy-unchecked-mul-mints-massive-supply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bonding-curve-buy-unchecked-mul-mints-massive-supply.yaml
Source: defimon-2026-04/pearldex-nlamm-40K + auditooor-fire14-worker-kk
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BondingCurveBuyUncheckedMulMintsMassiveSupply(AbstractDetector):
    ARGUMENT = "bonding-curve-buy-unchecked-mul-mints-massive-supply"
    HELP = "Bonding-curve buy() multiplies a user-supplied amount by a curve coefficient inside `unchecked { }` with no upper-bound check. Overflow wraps the cost down or the output up, minting massive supply for trivial input."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bonding-curve-buy-unchecked-mul-mints-massive-supply.yaml"
    WIKI_TITLE = "Bonding-curve buy(): unchecked multiplication wraps overflow, mints massive token supply"
    WIKI_DESCRIPTION = "A bonding-curve (NLAMM, linear-curve, sigmoid AMM, etc.) `buy()` / `mint()` entry-point computes the cost-of-tokens or tokens-for-cost relation as a multiplication of two large operands inside a Solidity `unchecked { ... }` block. Solidity 0.8's automatic overflow check is suppressed there, so a sufficiently large input wraps past 2**256, producing either a tiny cost figure (so attacker pays nothing) or a tiny tokens-out figure (so attacker has gamed the arithmetic). The attacker mints a manipulated supply, then sells into the paired AMM pool to drain real assets."
    WIKI_EXPLOIT_SCENARIO = "PearlDex Feb 2026, $40,300 across 5 pools: NLAMM `buy()` had `unchecked { uint256 cost = desired * step / 1e18; }` with `step` being the curve's per-token coefficient. Attacker passed `desired = 2**240`. The product wrapped to a tiny number, the contract took ~0 USDT, and minted 2**240 game tokens. Attacker then sold those tokens into IRON-ORE/USDT / COAL/USDT / WOOD/USDT / SAND/USDT / CLAY/USDT pools, draining 7.8 + 8.3 + 9.5 + 6.5 + 8.2 K USDT respectively."
    WIKI_RECOMMENDATION = "Either remove the `unchecked` block entirely (Solidity 0.8 will revert on overflow), or precede the multiplication with explicit bounds: `require(desired <= MAX_BUY); require(step <= MAX_STEP);` such that the worst-case product fits in uint256. Preferred: use `FullMath.mulDiv` from Uniswap's library, which handles 512-bit intermediates safely. Property test: every buy() call with realistic max input must NOT wrap, and `tokensMinted` must be monotone in `value`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bondingCurve|BondingCurve|NLAMM|LinearCurve|virtualReserve|reserveBase|theta|slope|step|priceFactor|coefficient|curveK|curveMultiplier|unitPrice|emissionMultiplier|pricePerToken|curveRate)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(buy|purchase|mint|deposit|swap|invest|enter)\\w*$'}, {'function.body_contains_regex': '(?is)unchecked\\s*\\{[^}]*(?:(?:msg\\.value|\\b(?:amount|amountIn|amountOut|value|desired|desiredTokens|requested|requestedTokens|requestedShares|tokensOut|tokensIn|tokenAmount|shares|qty|quantity|cost|toMint|mintAmount|buyAmount|depositAmount|inputAmount|baseAmount)\\b)\\s*\\*\\s*\\b(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|reserve|virtualReserve|unitPrice|price|rate|multiplier|emissionMultiplier|curveMultiplier|pricePerToken|curveRate|weight|scalar)\\b|\\b(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|reserve|virtualReserve|unitPrice|price|rate|multiplier|emissionMultiplier|curveMultiplier|pricePerToken|curveRate|weight|scalar)\\b\\s*\\*\\s*(?:msg\\.value|\\b(?:amount|amountIn|amountOut|value|desired|desiredTokens|requested|requestedTokens|requestedShares|tokensOut|tokensIn|tokenAmount|shares|qty|quantity|cost|toMint|mintAmount|buyAmount|depositAmount|inputAmount|baseAmount)\\b))[^}]*\\}'}, {'function.body_not_contains_regex': '(?is)require\\s*\\([^;]*(?:msg\\.value|\\b(?:desired|desiredTokens|requested|requestedTokens|requestedShares|amount|amountIn|amountOut|value|quantity|qty|buyAmount|depositAmount|inputAmount|tokensOut|tokensIn|tokenAmount|shares)\\b)\\s*<=?\\s*(?:MAX|maxBuy|maxAmount|maxInput|MAX_BUY|MAX_AMOUNT|type\\s*\\(\\s*uint\\d*\\s*\\)\\.max|2\\s*\\*\\*\\s*\\d+|[^;]*/\\s*(?:scale|theta|k|slope|coefficient|curveK|step|factor|priceFactor|reserve|virtualReserve|unitPrice|price|rate|multiplier|emissionMultiplier|curveMultiplier|pricePerToken|curveRate|weight|scalar))|FullMath\\.mulDiv\\s*\\(|FixedPointMathLib\\.mulDiv(?:Down|Up)?\\s*\\(|Math\\.mulDiv\\s*\\(|mulDiv(?:Down|Up)?\\s*\\(|SafeMath\\.mul\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" - bonding-curve-buy-unchecked-mul-mints-massive-supply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
