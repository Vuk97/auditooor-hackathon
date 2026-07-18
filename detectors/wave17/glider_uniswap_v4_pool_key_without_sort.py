"""
glider-uniswap-v4-pool-key-without-sort — generated from reference/patterns.dsl/glider-uniswap-v4-pool-key-without-sort.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v4-pool-key-without-sort.yaml
Source: glider/uniswap-v4-pool-key-used-without-first-comparing-i
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV4PoolKeyWithoutSort(AbstractDetector):
    ARGUMENT = "glider-uniswap-v4-pool-key-without-sort"
    HELP = "Uniswap V4 PoolKey built without ensuring currency0 < currency1."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v4-pool-key-without-sort.yaml"
    WIKI_TITLE = "Uniswap V4 PoolKey missing currency sort"
    WIKI_DESCRIPTION = "`PoolKey.currency0` must be the lexicographically-smaller token address. Without sorting, the resulting pool id differs from the canonical one, leading to silent failures, routing to uninitialised pools, or duplicate liquidity fragmentation."
    WIKI_EXPLOIT_SCENARIO = "Adapter computes `PoolKey(tokenA, tokenB, fee, spacing, hook)` with user-supplied ordering. When the user passes the tokens in the wrong order, the manager treats this as a distinct pool with zero liquidity; the swap reverts or mis-routes, trapping funds or inflating slippage."
    WIKI_RECOMMENDATION = "Always sort: `(currency0, currency1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA)` before constructing a PoolKey. Or delegate to the v4 helper."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'PoolKey|IPoolManager|v4-core'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'PoolKey\\s*\\('}, {'function.body_contains_regex': 'currency0\\s*:|currency1\\s*:'}, {'function.body_not_contains_regex': 'currency0\\s*<\\s*currency1|toId\\s*\\(|sortTokens|currencyA\\s*<\\s*currencyB'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-uniswap-v4-pool-key-without-sort: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
