"""
tree-tail-removal-no-size-decrement — generated from reference/patterns.dsl/tree-tail-removal-no-size-decrement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py tree-tail-removal-no-size-decrement.yaml
Source: code4arena/slice_ac-GTE-Spot-M03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TreeTailRemovalNoSizeDecrement(AbstractDetector):
    ARGUMENT = "tree-tail-removal-no-size-decrement"
    HELP = "Linked-list or tree `remove`/`cancel` path updates prev/next pointers or deletes a node slot but forgets to decrement the size counter. Off-by-one accumulates into unbounded growth and stale iteration bounds."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/tree-tail-removal-no-size-decrement.yaml"
    WIKI_TITLE = "Linked structure removal missing size-counter decrement"
    WIKI_DESCRIPTION = "A contract maintains an off-chain view (size/length/count) of a hand-rolled linked structure. The `remove`/`cancel`/`pop` function edits pointer fields or deletes slots, but the counter decrement only lives in the 'normal' branch — the tail, head, or single-entry branch silently skips the decrement. Consumers relying on the counter (iteration bounds, average-price calculation, tree rebalancing) co"
    WIKI_EXPLOIT_SCENARIO = "CLOB tracks `numOrders` for a price level. `_remove(id)` decrements the counter on internal-node removal. When the tail order is cancelled the else-branch clears `orders[id]` and rewires `tail` but forgets `numOrders--`. Attacker repeatedly places-and-cancels at a price level; `numOrders` inflates without bound. Downstream `maxLimitsPerTx` comparison never trips, enabling DoS. Arithmetic ratios li"
    WIKI_RECOMMENDATION = "Place the size-- (or `length--`) at the single exit point of the removal function, not inside one of the branches. Unit-test every structural branch (head, tail, internal, single-entry, empty) to observe counter changes."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(tree|queue|list|book)\\.(size|length|count)|(numOrders|orderCount|queueLength)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(remove|delete|pop|cancel|unlink|_remove|_delete)'}, {'function.body_contains_regex': '\\.next\\s*=|\\.prev\\s*=|head\\s*=|tail\\s*=|delete\\s+\\w+\\[\\w+\\]'}, {'function.body_not_contains_regex': '(size|length|count|numOrders|orderCount|queueLength)\\s*--|(size|length|count|numOrders|orderCount|queueLength)\\s*-=\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — tree-tail-removal-no-size-decrement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
