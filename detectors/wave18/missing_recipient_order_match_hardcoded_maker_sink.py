"""
missing-recipient-order-match-hardcoded-maker-sink — generated from reference/patterns.dsl/missing-recipient-order-match-hardcoded-maker-sink.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-recipient-order-match-hardcoded-maker-sink.yaml
Source: roadmap-slice-6-worker-bm-2026-05-17
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingRecipientOrderMatchHardcodedMakerSink(AbstractDetector):
    ARGUMENT = "missing-recipient-order-match-hardcoded-maker-sink"
    HELP = "Order-match settlement custodies assets and then pays proceeds/refunds to a hardcoded maker/caller sink instead of accepting an explicit recipient."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-recipient-order-match-hardcoded-maker-sink.yaml"
    WIKI_TITLE = "Order match settlement omits an explicit recipient sink"
    WIKI_DESCRIPTION = "Exchange match routines often custody both sides of an order while minting, merging, or netting assets, then pay the resulting proceeds and any refund out of the exchange balance. If that routine has no explicit recipient parameter and always routes proceeds/refunds to `takerOrder.maker`, `order.maker`, or `msg.sender`, routers and delegated operators cannot direct settlement to the intended accou"
    WIKI_EXPLOIT_SCENARIO = "A router or operator matches orders for a user and expects the fill proceeds or surplus refund to land at a supplied payout account. The match routine has no recipient argument, pulls assets into the exchange, executes the mint/merge/netting action, then transfers the exchange-held proceeds and refund to the order maker hardcoded in the order. The intended recipient is never represented in the set"
    WIKI_RECOMMENDATION = "Thread an explicit nonzero recipient/sink through the public match API and internal settlement helper, then route both proceeds and leftover refunds to that sink. If the protocol intentionally requires maker-self settlement, assert that invariant at the boundary and document it so routers cannot sup"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(OrderFilled|OrdersMatched|MatchType|_fillMakerOrders|_executeMatchCall|takerOrder|makerOrders)'}, {'contract.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^_?match(?:Orders|.*Order.*)$'}, {'function.body_contains_regex': '(?i)(_fillMakerOrders|_fillMakerOrder|_executeMatchCall)'}, {'function.body_contains_regex': '(?i)_transfer\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*,\\s*(?:takerOrder\\.maker|order\\.maker|msg\\.sender)\\s*,'}, {'function.body_contains_regex': '(?i)(refund|surplus|leftover|taking\\s*-\\s*fee|proceeds)'}, {'function.not_source_matches_regex': '(?i)\\baddress\\s+(?:to|recipient|receiver|beneficiary|payoutSink)\\b'}, {'function.body_not_contains_regex': '(?i)(?:require\\s*\\([^;]*(?:to|recipient|receiver|beneficiary|payoutSink)|InvalidRecipient|RecipientCannotBeZero|ZeroRecipient|recipient\\s*!=\\s*address\\s*\\(\\s*0\\s*\\))'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" — missing-recipient-order-match-hardcoded-maker-sink: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
