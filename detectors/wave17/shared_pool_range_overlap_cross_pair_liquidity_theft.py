"""
shared-pool-range-overlap-cross-pair-liquidity-theft — generated from reference/patterns.dsl/shared-pool-range-overlap-cross-pair-liquidity-theft.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py shared-pool-range-overlap-cross-pair-liquidity-theft.yaml
Source: auditooor-R75-c4-yield-2024-05-predy-49
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SharedPoolRangeOverlapCrossPairLiquidityTheft(AbstractDetector):
    ARGUMENT = "shared-pool-range-overlap-cross-pair-liquidity-theft"
    HELP = "Reallocation burns liquidity from (pool, tickLower, tickUpper) without scoping by pair — another pair sharing the same pool/range loses its liquidity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/shared-pool-range-overlap-cross-pair-liquidity-theft.yaml"
    WIKI_TITLE = "Shared Uniswap v3 position key across pairs lets one pair steal another's liquidity during reallocation"
    WIKI_DESCRIPTION = "Vaults that register multiple trading pairs on top of a single Uniswap v3 pool (e.g. USDC-quoted and ETH-quoted variants of the same ETH/USDC pool) must namespace their NFT positions by pair. If all pairs use the same `(owner=self, tickLower, tickUpper)` position key, Uniswap returns the combined liquidity. A reallocation of pair B burns the entire range, draining pair A's liquidity even though pa"
    WIKI_EXPLOIT_SCENARIO = "Operator registers pair 1 (quote=USDC) and pair 2 (quote=ETH) on the same ETH/USDC pool with identical tickLower/tickUpper. A user opens a gamma position on pair 1, supplying 10 ETH worth of liquidity. Price drifts out of pair 2's threshold; any MEV bot calls reallocate(pair=2). The burn removes all 10 ETH worth of liquidity from the shared position. Pair 1 internal state still claims 10 ETH of li"
    WIKI_RECOMMENDATION = "Encode pairId into the position key: either mint a fresh Uniswap v3 NFT per pair (most robust) or use distinct `(tickLower, tickUpper)` offsets per pair. Before reallocating, assert that pool.positions(key).liquidity equals the pair's internally-tracked liquidity."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(perp.*pool|gamma.*pool|vault.*pair|pair.*status)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(reallocate|burnLiquidity|collectFromPool|withdrawFromPool)'}, {'function.body_contains_regex': '\\.burn\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*,\\s*\\w+\\s*\\)|\\.positions\\s*\\('}, {'function.body_contains_regex': '(?i)(tickLower|tickUpper|lowerTick|upperTick)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(pairId|poolKey|positionKey.*pairId|liquidityByPair)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — shared-pool-range-overlap-cross-pair-liquidity-theft: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
