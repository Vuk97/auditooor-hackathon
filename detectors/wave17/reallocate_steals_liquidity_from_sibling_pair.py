"""
reallocate-steals-liquidity-from-sibling-pair — generated from reference/patterns.dsl/reallocate-steals-liquidity-from-sibling-pair.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reallocate-steals-liquidity-from-sibling-pair.yaml
Source: auditooor-R75-code4rena-2024-05-predy-49

Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReallocateStealsLiquidityFromSiblingPair(AbstractDetector):
    ARGUMENT = "reallocate-steals-liquidity-from-sibling-pair"
    HELP = "reallocate() uses the underlying UniV3 position as 'this pair's liquidity' but the pool has no per-pair partitioning — sibling pair with same range shares the slot."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reallocate-steals-liquidity-from-sibling-pair.yaml"
    WIKI_TITLE = "Reallocate assumes per-pair liquidity but UniV3 pool slot is shared across pairs"
    WIKI_DESCRIPTION = "Pairs are registered per (quoteToken, baseToken) but share the underlying Uniswap V3 pool. The `reallocate()` function burns the pair's liquidity using Uniswap's position slot, which is keyed only by tick range. If two pairs have the same upper/lower ticks, they collide on the same slot — pair B's reallocate removes liquidity belonging to pair A's users. All accounting (borrows, collateral, insura"
    WIKI_EXPLOIT_SCENARIO = "Operator registers Pair1 (USDC/ETH, USDC-quote) and Pair2 (USDC/ETH, ETH-quote) with identical tick ranges. User trades gamma on Pair1, adding liquidity to the shared UniV3 slot. Anyone triggers reallocate() on Pair2 (which has no liquidity of its own). Pair2's reallocate burns Pair1's liquidity; Pair1 users cannot close positions."
    WIKI_RECOMMENDATION = "Either (a) forbid duplicate tick range per pool at pair registration, (b) have each pair use a unique NFT position (different owner), or (c) track per-pair shares of the shared liquidity via an internal bookkeeping system. Registration check: `require(!isRangeUsed[pool][lower][upper])`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '(?i)reallocate\\w*|rebalance\\w*|migrate\\w*Range'}, {'function.body_contains_regex': '(?i)uniswapPool\\.burn|uniswapPool\\.mint|IUniswapV3Pool\\(|INonfungible'}, {'function.body_contains_regex': '(?i)lowerTick|upperTick|sqrtRatio\\w*'}, {'function.body_not_contains_regex': '(?i)pairId|require\\s*\\([^)]*uniswapPool\\s*!=|require\\s*\\([^)]*\\.pool\\s*==\\s*uniqueOwner|lpShare'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reallocate-steals-liquidity-from-sibling-pair: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
