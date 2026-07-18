"""
order-dll-prev-id-not-persisted — generated from reference/patterns.dsl/order-dll-prev-id-not-persisted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py order-dll-prev-id-not-persisted.yaml
Source: solodit-novel/slice_ac-OrderBook
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OrderDllPrevIdNotPersisted(AbstractDetector):
    ARGUMENT = "order-dll-prev-id-not-persisted"
    HELP = "Doubly-linked order list updates `memOrder.prevOrderId` (local memory copy) but never writes it back to the `orders[id]` storage slot. List is permanently broken forward but not backward."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/order-dll-prev-id-not-persisted.yaml"
    WIKI_TITLE = "DLL prevOrderId updated in memory, never written to storage"
    WIKI_DESCRIPTION = "When inserting into a doubly-linked list, both the new node's prev/next and the neighbors must be written back to storage. A common bug is operating on a `memory` copy of the new order and forgetting the final `orders[id] = memOrder` assignment."
    WIKI_EXPLOIT_SCENARIO = "Market maker places chained limit orders. DLL backward-walk from the tail reads prevOrderId=0 for all but the latest, so cancellation/iteration from the tail returns wrong set, potentially enabling double-fill or order-loss."
    WIKI_RECOMMENDATION = "After mutating a memory struct, write it back explicitly: `orders[newId] = memOrder;`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'prevOrderId|nextOrderId|OrderList|DoublyLinkedList'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(insert|_insert|placeOrder|_placeOrder|_addToList|linkOrder)'}, {'function.body_contains_regex': 'memOrder\\.prevOrderId\\s*=|newOrder\\.prevOrderId\\s*=|\\.prevOrderId\\s*='}, {'function.body_not_contains_regex': 'orders\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*(memOrder|newOrder)|orders\\s*\\[[^\\]]+\\]\\.prevOrderId\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — order-dll-prev-id-not-persisted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
