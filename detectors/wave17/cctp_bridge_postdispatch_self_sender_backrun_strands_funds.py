"""
cctp-bridge-postdispatch-self-sender-backrun-strands-funds — generated from reference/patterns.dsl/cctp-bridge-postdispatch-self-sender-backrun-strands-funds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cctp-bridge-postdispatch-self-sender-backrun-strands-funds.yaml
Source: auditooor-R73-fixdiff-mined-hyperlane-ac297dac9c
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CctpBridgePostdispatchSelfSenderBackrunStrandsFunds(AbstractDetector):
    ARGUMENT = "cctp-bridge-postdispatch-self-sender-backrun-strands-funds"
    HELP = "A CCTP-integrating bridge hook that calls postDispatch for any message whose id was \"latest dispatched\" allows an attacker to backrun a legitimate transferRemote with a second postDispatch call that produces a phantom Circle hook message for the same messageId; on the destination this marks isVeri"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cctp-bridge-postdispatch-self-sender-backrun-strands-funds.yaml"
    WIKI_TITLE = "CCTP bridge postDispatch can be backrun to mark message verified without mint"
    WIKI_DESCRIPTION = "Hyperlane's TokenBridgeCctp glues CCTP attestation to Hyperlane messaging. The intended flow: transferRemote → internal dispatch(id) → hook.postDispatch(id) creates a CCTP hook message that Circle attesters co-sign. The destination uses the Circle-attested hook to simultaneously flip isVerified[id] and invoke the Circle mint. The original postDispatch accepted any message whose id passed _isLatest"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice calls transferRemote for 10k USDC → burn + dispatch(id=H) + hookPostDispatch(id=H) with sender=address(this). (2) Attacker in next block calls TokenBridgeCctp.postDispatch(metadata=\"\", message=formatMessage(sender=ATTACKER, id=H)). _isLatestDispatched(H) still returns true. A second Circle hook message for id=H is created. (3) On destination, the attacker's cheaper/faster hook message "
    WIKI_RECOMMENDATION = "In postDispatch, reject any message whose `senderAddress()` is not `address(this)`. Only transferRemote sets sender=address(this); any attacker-crafted message will have a different sender. Add a canonical test: deploy the bridge, legitimately transferRemote, then attempt postDispatch with a message"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'TokenBridgeCctp|CctpBase|transferRemote|postDispatch'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(postDispatch|_postDispatch)$'}, {'function.body_contains_regex': '(Circle|TokenMessenger|depositForBurn|cctp|CCTP).*(hook|message\\.id|isLatestDispatched)'}, {'function.body_not_contains_regex': 'senderAddress\\s*\\(\\s*\\)\\s*==\\s*address\\s*\\(\\s*this\\s*\\)|message\\.senderAddress\\(\\)\\s*==\\s*address\\(this\\)|InvalidPostDispatchSender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cctp-bridge-postdispatch-self-sender-backrun-strands-funds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
