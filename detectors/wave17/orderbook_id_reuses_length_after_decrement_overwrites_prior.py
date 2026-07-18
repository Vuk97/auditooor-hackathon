"""
orderbook-id-reuses-length-after-decrement-overwrites-prior — generated from reference/patterns.dsl/orderbook-id-reuses-length-after-decrement-overwrites-prior.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py orderbook-id-reuses-length-after-decrement-overwrites-prior.yaml
Source: lisa-mine-r99-case-02973-sherlock-knox-2022-09
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OrderbookIdReusesLengthAfterDecrementOverwritesPrior(AbstractDetector):
    ARGUMENT = "orderbook-id-reuses-length-after-decrement-overwrites-prior"
    HELP = "Order/position book derives a new entry's id from `length + 1` (then assigns the new entry to slot `id = length`) without maintaining a free-list of removed ids. Because `_remove` decrements `length` in-place, a subsequent `_insert` reuses the id of the most recent surviving entry — overwriting that"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/orderbook-id-reuses-length-after-decrement-overwrites-prior.yaml"
    WIKI_TITLE = "Order book uses array length as id allocator without recycling — _remove + _insert overwrites a live order"
    WIKI_DESCRIPTION = "Pattern fires when an internal `_insert`-style function increments `index.length` and uses the post-increment value as the new id, while the corresponding `_remove` decrements `index.length` in-place without preserving the removed slot's id. The two operations are not inverse: insert writes to `id = length`, remove shifts `length`, but the surviving entries keep their ids. After [insert A, insert "
    WIKI_EXPLOIT_SCENARIO = "Alice places an order with price=10 → id=1, length=1. Bob places an order with price=20 → id=2, length=2. Alice cancels her order → length=1 (Bob's order is still id=2 with B's owner & price). Carol places an order with price=30 → length becomes 2, new id = length = 2, contract writes Carol's order over Bob's slot. Bob's order silently disappears: his owner address is gone, his funds remain escrow"
    WIKI_RECOMMENDATION = "Maintain a free-list of removed ids (push to a `uint256[] freeIds` in `_remove`, pop from it first in `_insert`). Alternatively, use a monotonic `uint256 nextId` counter that is only ever incremented and never reset — then use `length` only as a count, not as an id. Never derive an id from `length` "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '_insert|_addOrder|addLimitOrder|placeBid|insertOrder'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '_insert|_addLimitOrder|_placeBid|_insertOrder'}, {'function.body_contains_regex': '(index|orders|book|positions)\\.length\\s*=\\s*(?:.*\\?)?\\s*(index|orders|book|positions)\\.length\\s*\\+\\s*1'}, {'function.body_contains_regex': 'uint256\\s+\\w+\\s*=\\s*(index|orders|book|positions)\\.length\\s*;'}, {'function.body_not_contains_regex': '(freeIds|reusableIds|nextId\\+\\+|nextOrderId\\+\\+|recycled|popFreeId|reservedIds)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — orderbook-id-reuses-length-after-decrement-overwrites-prior: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
