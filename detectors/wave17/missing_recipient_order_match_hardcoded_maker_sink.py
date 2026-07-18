"""
missing-recipient-order-match-hardcoded-maker-sink - narrow fee-redirect sibling.

Detects a match or settle path that hardcodes proceeds or refunds to the maker
or msg.sender instead of taking an explicit payout recipient.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingRecipientOrderMatchHardcodedMakerSink(AbstractDetector):
    ARGUMENT = "missing-recipient-order-match-hardcoded-maker-sink-b15"
    HELP = (
        "A match or settle path hardcodes proceeds or refunds to the maker or "
        "msg.sender instead of taking an explicit payout recipient."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "missing-recipient-order-match-hardcoded-maker-sink.yaml"
    )
    WIKI_TITLE = "Order match settlement omits an explicit recipient sink"
    WIKI_DESCRIPTION = (
        "A settlement routine can custody both sides of an order and then pay "
        "the resulting proceeds or refund to a hardcoded maker or caller sink "
        "instead of threading an explicit recipient. That is a recipient sink "
        "omission."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A router or operator matches orders for a user and expects the fill "
        "proceeds or surplus refund to land at a supplied payout account. The "
        "match routine has no recipient argument, pulls assets into the "
        "exchange, executes the settlement action, then transfers the "
        "exchange-held proceeds and refund to the order maker hardcoded in the "
        "order."
    )
    WIKI_RECOMMENDATION = (
        "Thread an explicit payout recipient through the public match API and "
        "internal settlement helper, then route both proceeds and leftover "
        "refunds to that sink."
    )

    _PRECONDITIONS = [
        {"contract.source_matches_regex": "(?i)(OrderFilled|OrdersMatched|makerOrders|takerOrder|refund|surplus|proceeds)"}
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {"function.name_matches": "(?i)^(matchOrders|matchOrder|executeMatchCall|fillOrder|_fillMakerOrders|_fillMakerOrder|_matchOrder)$"},
        {"function.body_contains_regex": "(?is)(refund|surplus|leftover|proceeds)"},
        {"function.body_contains_regex": "(?is)_transfer\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*,\\s*(?:takerOrder\\.maker|order\\.maker|msg\\.sender)\\s*,"},
        {"function.not_source_matches_regex": "(?i)\\baddress\\s+(?:to|recipient|receiver|beneficiary|payoutSink)\\b"},
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture)\\b"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    " - missing-recipient-order-match-hardcoded-maker-sink: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
