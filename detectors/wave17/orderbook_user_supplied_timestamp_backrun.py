"""
orderbook-user-supplied-timestamp-backrun — generated from reference/patterns.dsl/orderbook-user-supplied-timestamp-backrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py orderbook-user-supplied-timestamp-backrun.yaml
Source: defihacklabs/2025-08-EverValueCoin
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OrderbookUserSuppliedTimestampBackrun(AbstractDetector):
    ARGUMENT = "orderbook-user-supplied-timestamp-backrun"
    HELP = "On-chain orderbook accepts a user-supplied `timestamp` parameter and stores it as the order's placement time. Attacker spoofs an ancient timestamp, jumping the matching priority queue."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/orderbook-user-supplied-timestamp-backrun.yaml"
    WIKI_TITLE = "Orderbook trusts caller-supplied timestamp for matching priority"
    WIKI_DESCRIPTION = "When the matching engine uses `order.timestamp` as a tiebreaker (price-time priority, oldest-first cancel queue, etc.), any addOrder path that takes the timestamp as a parameter without asserting it matches `block.timestamp` lets attackers jump the queue. Because older orders are considered before newer ones at the same price, the attacker becomes the first-filled order on the book."
    WIKI_EXPLOIT_SCENARIO = "EverValueCoin (Aug 2025, 100k USD): attacker calls `orderbook.addNewOrder(pairId, q, p, true, timestamp=1)` where timestamp is set to unix-epoch 1. Orderbook stores the order with this stale timestamp, then ranks it ahead of every honest bid at the same price level. Attacker then routes a legitimate-looking swap through the book and crosses against their own stale order at a manipulated price."
    WIKI_RECOMMENDATION = "Never trust caller-supplied timestamps. Write `block.timestamp` into the order server-side. If historical timestamps are needed for replay, require them to equal `block.timestamp` at the time of insertion, or require an EIP-712 signed intent with the timestamp inside the signed struct."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'orderbook|OrderBook|addNewOrder|createOrder'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(addNewOrder|createOrder|placeOrder|submitOrder|insertOrder)'}, {'function.has_param_name_matching': '(timestamp|_timestamp|orderTime|placedAt|t)'}, {'function.has_param_of_type': 'uint256'}, {'function.body_contains_regex': '\\.timestamp\\s*=\\s*_timestamp|\\.orderTime\\s*=\\s*_timestamp|\\.placedAt\\s*=\\s*\\w*[Tt]imestamp|orders\\s*\\[\\s*\\w+\\s*\\]\\.\\w*timestamp'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*_?timestamp\\s*<=\\s*block\\.timestamp|require\\s*\\(\\s*_?timestamp\\s*>=\\s*block\\.timestamp|block\\.timestamp\\s*=='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — orderbook-user-supplied-timestamp-backrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
