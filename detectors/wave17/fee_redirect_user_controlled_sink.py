"""
fee-redirect-user-controlled-sink - generated from reference/patterns.dsl/fee-redirect-user-controlled-sink.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-redirect-user-controlled-sink.yaml
Source: auditooor-P1-09-fee-redirect-capability-lift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeRedirectUserControlledSink(AbstractDetector):
    ARGUMENT = "fee-redirect-user-controlled-sink"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags public fee withdrawal or distribution paths that compute/read a protocol fee amount but send it to msg.sender or a caller supplied recipient instead of a configured fee sink."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-redirect-user-controlled-sink.yaml"
    WIKI_TITLE = "Protocol fee redirected to caller controlled sink"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. Protocol revenue paths should route fee amounts to a configured treasury, fee collector, or authenticated operator. This pattern catches the broader sibling of the instance-specific caller-fee detector: a public/external fee collection, withdrawal, sweep, or distribution function references protocol fee state and transfers that fee amount to msg.sender or a c"
    WIKI_EXPLOIT_SCENARIO = "A vault accrues protocol fees in `accruedFee` and exposes `withdrawProtocolFee(address feeRecipient)`. Because the function is public and transfers `feeAmount` to the supplied `feeRecipient`, any caller can pass their own address and drain fees that should have gone to `treasury`."
    WIKI_RECOMMENDATION = "Route protocol fee withdrawals to the configured treasury or fee collector, or restrict caller selected fee sinks to an authenticated role. If a caller incentive is intentional, keep it in a separate capped reward variable and document it separately from protocol fees."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(treasury|feeRecipient|feeCollector|protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|accruedFee|pendingFee)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(collect|claim|distribute|withdraw|sweep|settle|execute|harvest)(?:.*fee)?|fee.*(collect|claim|distribute|withdraw|sweep|settle|execute|harvest)'}, {'function.body_contains_regex': '(?is)\\b(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|accruedFee|pendingFee|feeAmount|fee)\\b'}, {'function.body_contains_regex': '(?is)(?:\\b(?:uint\\d*\\s+)?(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|feeAmount|fee)\\s*=\\s*[^;]+;|(?:accruedFee|pendingFee|protocolFees|platformFees|royaltyFees|keeperFees|callerFees)\\s*(?:\\[[^\\]]+\\])?\\s*(?:=|\\+=|-=)|\\b(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|feeAmount|fee)\\b\\s*=\\s*[^;]+;)'}, {'function.body_contains_regex': '(?is)(?:safeTransfer|transfer|sendValue)\\s*\\(\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\)|caller|recipient|receiver|to|beneficiary|feeRecipient|feeReceiver)\\s*,\\s*(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|feeAmount|fee|accruedFee|pendingFee)\\b|payable\\s*\\(\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\)|caller|recipient|receiver|to|beneficiary|feeRecipient|feeReceiver)\\s*\\)\\s*\\.\\s*(?:transfer|send)\\s*\\(\\s*(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|feeAmount|fee|accruedFee|pendingFee)\\b'}, {'function.body_not_contains_regex': '(?is)(onlyOwner|onlyRole|onlyAdmin|onlyKeeper|requiresAuth|auth|nonReentrant|AccessControl|require\\s*\\(\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\))\\s*==\\s*(?:owner|admin|keeper|treasury|feeCollector|feeRecipient)|require\\s*\\(\\s*(?:owner|admin|keeper|treasury|feeCollector|feeRecipient)\\s*==\\s*(?:msg\\.sender|_msgSender\\s*\\(\\s*\\)))'}, {'function.body_not_contains_regex': '(?is)(?:safeTransfer|transfer|sendValue)\\s*\\(\\s*(?:treasury|feeCollector|protocolVault|protocolTreasury|feeSink|configuredFeeRecipient)\\s*,\\s*(?:protocolFee|platformFee|serviceFee|treasuryFee|royaltyFee|keeperFee|callerFee|feeAmount|fee|accruedFee|pendingFee)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - fee-redirect-user-controlled-sink: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
