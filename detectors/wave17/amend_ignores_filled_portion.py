"""
amend-ignores-filled-portion — generated from reference/patterns.dsl/amend-ignores-filled-portion.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amend-ignores-filled-portion.yaml
Source: code4arena/slice_ac-GTE-Perps-M09
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmendIgnoresFilledPortion(AbstractDetector):
    ARGUMENT = "amend-ignores-filled-portion"
    HELP = "amendOrder updates quantity/size without accounting for the already-filled portion. A partially-filled maker order can be amended to a smaller size, but the engine keeps filling it up to the new size as if nothing was filled before."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amend-ignores-filled-portion.yaml"
    WIKI_TITLE = "amendOrder ignores already-filled quantity"
    WIKI_DESCRIPTION = "When a resting maker order has filled 60% of its original quantity and the maker calls `amend(size = newSize)`, the correct semantic is `newSize >= alreadyFilled` and `remaining = newSize - filled`. If the amend path writes `order.size = newSize` and leaves `order.filled` untouched — or resets filled to zero — the order can take additional fills beyond what the maker ever authorized in aggregate."
    WIKI_EXPLOIT_SCENARIO = "Maker places a 10-BTC sell. Taker fills 6 BTC. Maker amends to 8 BTC expecting 2 more BTC of capacity. Because the amend overwrites size and leaves filled=6 but the matching engine's `remaining = size - filled = 2`, this path happens to be safe IF filled is preserved. If the amend resets filled=0, the maker is now exposed to another 8 BTC of unwanted fills, 14 BTC total — the exact bug in GTE-Perp"
    WIKI_RECOMMENDATION = "Inside amend: `require(newSize >= order.filled, 'cannot-shrink-below-filled')`. Never clear or reset `order.filled` on amend; only `order.size` may change."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(amend|modify|resize)Order|filled'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(amendOrder|modifyOrder|resizeOrder|_amend)'}, {'function.body_contains_regex': '(orders\\s*\\[\\s*\\w+\\s*\\]\\.\\w*qty|orders\\s*\\[\\s*\\w+\\s*\\]\\.amount|orders\\s*\\[\\s*\\w+\\s*\\]\\.size)\\s*='}, {'function.body_not_contains_regex': '(orders\\s*\\[\\s*\\w+\\s*\\]\\.filled|require\\s*\\(\\s*newQty\\s*>=\\s*\\w+\\.filled|require\\s*\\(\\s*newSize\\s*>=\\s*\\w*filled)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amend-ignores-filled-portion: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
