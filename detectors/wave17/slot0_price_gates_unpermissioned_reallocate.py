"""
slot0-price-gates-unpermissioned-reallocate — generated from reference/patterns.dsl/slot0-price-gates-unpermissioned-reallocate.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py slot0-price-gates-unpermissioned-reallocate.yaml
Source: auditooor-R75-c4-yield-2024-05-predy-209
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Slot0PriceGatesUnpermissionedReallocate(AbstractDetector):
    ARGUMENT = "slot0-price-gates-unpermissioned-reallocate"
    HELP = "Anyone can call reallocate(); branching decision uses slot0() spot price — trivially manipulated via sandwich to force an out-of-range reallocation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/slot0-price-gates-unpermissioned-reallocate.yaml"
    WIKI_TITLE = "Unpermissioned LP reallocation triggered by spot slot0 can be sandwiched to strip yield"
    WIKI_DESCRIPTION = "Yield vaults that wrap a concentrated-liquidity position (Uniswap v3 / v4) often expose an unpermissioned `reallocate()` so keepers and MEV bots can recenter the range. If the decision uses `pool.slot0()` (instant spot), an attacker can sandwich the call with a small swap that pushes price out of range, force the reallocation at a bad price, then unwind their swap. The LP pays the reallocation cos"
    WIKI_EXPLOIT_SCENARIO = "Predy Perp.reallocate(): attacker swaps ETH→USDC inside the target pool, shifting slot0 below tickLower. reallocate sees isOutOfRange=true, calls swapForOutOfRange which burns liquidity at the manipulated price. Attacker swaps back; LP realizes a loss equal to the spread × liquidity."
    WIKI_RECOMMENDATION = "Gate the out-of-range decision on a TWAP (pool.observe over ≥ 30 minutes) or a secondary oracle (Chainlink / Pyth) with bounded deviation from slot0. For permissionless keepers, add a bounty-per-tick-deviation schedule so a manipulated call wastes the attacker's gas rather than the LP's capital."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(reallocate|rebalance|shiftRange|rerange|recenter)'}, {'function.body_contains_regex': '\\.slot0\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '(?i)(observe\\s*\\(|twap|getTimeWeighted|oracleCardinality|secondsAgo|twapSeconds)'", "!function.has_modifier: '^(onlyOwner|onlyKeeper|onlyAdmin|onlyRole)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — slot0-price-gates-unpermissioned-reallocate: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
