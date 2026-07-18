"""
withdraw-claim-recipient-ignored-hardcoded-sink - generated from reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdraw-claim-recipient-ignored-hardcoded-sink.yaml
Source: roadmap-slice-6-lane-s2-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawClaimRecipientIgnoredHardcodedSink(AbstractDetector):
    ARGUMENT = "withdraw-claim-recipient-ignored-hardcoded-sink"
    HELP = "Withdraw / claim / refund path takes a recipient-like parameter but routes the payout to a different hardcoded sink instead of that parameter."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdraw-claim-recipient-ignored-hardcoded-sink.yaml"
    WIKI_TITLE = "Withdraw or claim takes recipient but pays a different sink"
    WIKI_DESCRIPTION = "User-facing payout paths often accept `recipient`, `receiver`, `to`, or `beneficiary` so routers, custodians, and delegated executors can separate the caller from the payout sink. This row fires when the function still transfers value to `msg.sender`, `owner()`, `request.account()`, or another hardcoded sink even though a recipient-like parameter exists. The final payout edge is therefore not boun"
    WIKI_EXPLOIT_SCENARIO = "A vault exposes `withdraw(address recipient, uint256 shares)`. Integrators call it through a router and expect funds to land on a custody address. The function burns shares for the user, computes assets, but ends with `asset.safeTransfer(msg.sender, assets)` or `payable(msg.sender).call{value: assets}(\"\")`. The router receives the payout while the intended recipient is ignored, breaking settleme"
    WIKI_RECOMMENDATION = "Bind the final payout edge to the explicit recipient parameter. Every branch that forwards value or refunds leftovers should transfer to `recipient` (or a validated normalized alias of it), not to `msg.sender` or another default sink. If the protocol intentionally requires self-withdrawal, remove th"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(withdraw|redeem|claim|refund|release|exit|payout|vault|escrow|router)'}, {'contract.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(withdraw|redeem|claim|claimFees|claimReward|refund|release|exit|bridgeExit|payout)[A-Za-z0-9_]*$'}, {'function.has_param_of_type': 'address'}, {'function.has_param_name_matching': '(?i)^(recipient|receiver|to|beneficiary|refundTo|payoutSink)$'}, {'function.body_contains_regex': '(?i)(?:\\w+\\s*\\.\\s*)?(?:safeTransfer|transfer)\\s*\\(\\s*(?:msg\\.sender|owner\\s*\\(\\s*\\)|account|request\\.account\\s*\\(\\s*\\)|withdrawal\\.account\\s*\\(\\s*\\)|position\\.owner|claim\\.owner)\\s*,|payable\\s*\\(\\s*(?:msg\\.sender|owner\\s*\\(\\s*\\)|account|request\\.account\\s*\\(\\s*\\)|withdrawal\\.account\\s*\\(\\s*\\)|position\\.owner|claim\\.owner)\\s*\\)\\s*\\.(?:call|transfer|send)'}, {'function.body_not_contains_regex': '(?i)(?:\\w+\\s*\\.\\s*)?(?:safeTransfer|transfer)\\s*\\(\\s*(?:recipient|receiver|to|beneficiary|refundTo|payoutSink)\\s*,|payable\\s*\\(\\s*(?:recipient|receiver|to|beneficiary|refundTo|payoutSink)\\s*\\)\\s*\\.(?:call|transfer|send)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" - withdraw-claim-recipient-ignored-hardcoded-sink: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
