"""
recipient-validation-ignored-or-hardcoded-sink

Detects payout functions that accept a recipient-like address, validate or
mention it, but send value to a different hardcoded sink.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RecipientValidationIgnoredOrHardcodedSink(AbstractDetector):
    ARGUMENT = "recipient-validation-ignored-or-hardcoded-sink"
    HELP = (
        "Payout path accepts a recipient-like parameter but sends assets to "
        "msg.sender, owner, maker, account, or another hardcoded sink."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Recipient parameter is ignored on payout"
    WIKI_DESCRIPTION = (
        "A withdraw, claim, refund, release, settlement, or repay path accepts "
        "a recipient-like parameter but the final transfer uses a different "
        "sink. A zero-address check on the unused recipient is not enough "
        "because the value-moving edge is not bound to that recipient."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A router calls withdraw(recipient, shares) expecting proceeds to land "
        "on the supplied recipient. The function burns or debits the caller, "
        "then transfers assets to msg.sender or another default sink instead."
    )
    WIKI_RECOMMENDATION = (
        "Send every payout and refund edge to the explicit recipient, or remove "
        "the parameter and assert the protocol only supports self-withdrawal."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "(?i)(withdraw|redeem|claim|refund|release|exit|payout|"
                "vault|escrow|router|settle|repay|order|maker|recipient)"
            )
        }
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                "(?i)^(withdraw|redeem|claim|claimFees|claimReward|refund|"
                "release|exit|bridgeExit|payout|settle|repay|match)[A-Za-z0-9_]*$"
            )
        },
        {"function.has_param_of_type": "address"},
        {
            "function.has_param_name_matching": (
                "(?i)^(recipient|receiver|to|beneficiary|refundTo|payoutSink)$"
            )
        },
        {
            "function.body_contains_regex": (
                "(?i)(safeTransfer|transfer)\\s*\\(\\s*"
                "(?:msg\\.sender|owner\\s*\\(\\s*\\)|account|"
                "request\\.account\\s*\\(\\s*\\)|withdrawal\\.account\\s*\\(\\s*\\)|"
                "position\\.owner|claim\\.owner|takerOrder\\.maker|order\\.maker)\\s*,|"
                "payable\\s*\\(\\s*"
                "(?:msg\\.sender|owner\\s*\\(\\s*\\)|account|"
                "request\\.account\\s*\\(\\s*\\)|withdrawal\\.account\\s*\\(\\s*\\)|"
                "position\\.owner|claim\\.owner|takerOrder\\.maker|order\\.maker)\\s*\\)"
                "\\s*\\.(?:call|transfer|send)"
            )
        },
        {
            "function.body_not_contains_regex": (
                "(?i)(safeTransfer|transfer)\\s*\\(\\s*"
                "(?:recipient|receiver|to|beneficiary|refundTo|payoutSink)\\s*,|"
                "payable\\s*\\(\\s*"
                "(?:recipient|receiver|to|beneficiary|refundTo|payoutSink)\\s*\\)"
                "\\s*\\.(?:call|transfer|send)"
            )
        },
        {"function.not_in_skip_list": True},
    ]

    _INCLUDE_LEAF_HELPERS = False

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
                    " - recipient-validation-ignored-or-hardcoded-sink: "
                    "recipient parameter is not bound to the payout sink.",
                ]
                results.append(self.generate_result(info))
        return results
