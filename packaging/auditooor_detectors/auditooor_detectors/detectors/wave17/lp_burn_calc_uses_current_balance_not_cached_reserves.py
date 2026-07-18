"""
lp-burn-calc-uses-current-balance-not-cached-reserves — generated from reference/patterns.dsl/lp-burn-calc-uses-current-balance-not-cached-reserves.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lp-burn-calc-uses-current-balance-not-cached-reserves.yaml
Source: auditooor-R76-rekt-spartan-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LpBurnCalcUsesCurrentBalanceNotCachedReserves(AbstractDetector):
    ARGUMENT = "lp-burn-calc-uses-current-balance-not-cached-reserves"
    HELP = "LP burn calculates withdrawal using `balanceOf(pool)` live instead of cached reserves. Flash-loan donation into the pool inflates balanceOf without minting LP, so burning LP releases the donated-plus-original tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lp-burn-calc-uses-current-balance-not-cached-reserves.yaml"
    WIKI_TITLE = "LP burn calculation reads live balanceOf instead of cached reserves, enabling flash-donate inflation"
    WIKI_DESCRIPTION = "Uniswap-V2-style pools track cached `_reserve0 / _reserve1` that are only updated via `sync()` / `_update()` on swap/mint/burn. If a pool computes user withdrawal as `userOut = lp * IERC20(token).balanceOf(address(this)) / totalSupply(LP)`, any attacker can donate a large amount of the underlying token into the pool (simple ERC20 transfer, no mint), inflating `balanceOf` without changing `totalSup"
    WIKI_EXPLOIT_SCENARIO = "Attacker holds 1M LP shares (out of 2M total; pool has 10M SPARTA + 10M WBNB). Attacker flash-loans 500M SPARTA and transfers it directly into the pool (not via addLiquidity). Pool now has balanceOf = 510M SPARTA, but totalSupply(LP) still = 2M. Attacker calls `burnLiquidity(1M)`. Formula: out = 1M * 510M / 2M = 255M SPARTA. Attacker receives 255M SPARTA + half of WBNB. Repays 500M flash loan, kee"
    WIKI_RECOMMENDATION = "Always use cached reserves (`_reserve0, _reserve1` updated atomically with mint/burn/swap) when computing user share conversion. If you must read `balanceOf`, apply a max-bound: `uint balance = min(balanceOf(this), cachedReserve + expectedDelta)`. Alternatively, `sync()` at the start of burn/mint an"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'AMM / LP pool burn-liquidity path computes withdrawal as `balanceOf(pool) * lp / totalSupply(lp)` where `balanceOf` is read live from the token contract rather than from a cached reserves variable.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)burnLiquidity|removeLiquidity|withdrawLP|redeemShares|calcLiquidityShare'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)balanceOf\\s*\\(\\s*address\\(this\\)\\s*\\)\\s*\\*|IERC20\\([^)]+\\)\\.balanceOf\\s*\\(\\s*address\\(this\\)\\s*\\)'}, {'function.body_not_contains_regex': '(?i)baseAmountPooled|tokenAmountPooled|_reserve0|_reserve1|cachedReserve|(\\_|)reserves\\s*\\[|getReserves\\(\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lp-burn-calc-uses-current-balance-not-cached-reserves: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
