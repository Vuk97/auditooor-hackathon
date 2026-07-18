"""
cross-chain-sender-not-bound-canonical — generated from reference/patterns.dsl/cross-chain-sender-not-bound-canonical.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-chain-sender-not-bound-canonical.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossChainSenderNotBoundCanonical(AbstractDetector):
    ARGUMENT = "cross-chain-sender-not-bound-canonical"
    HELP = "Cross-chain receive-side function does not bind msg.sender to the canonical bridge/messenger/endpoint — any EOA can call it directly and trigger finalization side-effects."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-chain-sender-not-bound-canonical.yaml"
    WIKI_TITLE = "Cross-chain receive-side entry point missing canonical-sender bind"
    WIKI_DESCRIPTION = "A receive-side entry point on a cross-chain messaging layer (`relayMessage`, `receiveMessage`, `finalizeDeposit`, `finalizeWithdrawal`, `handleMessage`, `handleBridgedCall`, `onMessageReceived`) must require that `msg.sender` is the canonical bridge / messenger / endpoint contract for the local chain. Without that bind, any EOA can invoke the function directly with forged parameters and trigger th"
    WIKI_EXPLOIT_SCENARIO = "An L2 contract exposes `finalizeDeposit(address to, uint256 amount, bytes proof)`. The function validates `proof` shape but never requires that `msg.sender == l2Messenger`. An attacker calls `finalizeDeposit` directly from a freshly-deployed EOA with a crafted but internally consistent proof blob that passes the local verification path, minting `amount` tokens to `to` on the L2 with no correspondi"
    WIKI_RECOMMENDATION = "At the top of every receive-side entry point enforce the canonical-sender bind explicitly: `require(msg.sender == messenger, 'not messenger')` or `require(IMessenger(messenger).xDomainMessageSender() == trustedRemote, 'bad remote')` — or attach an `onlyMessenger` / `onlyBridge` / `onlyRelayer` modif"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(relayMessage|receiveMessage|finalizeDeposit|finalizeWithdraw|handleMessage|_relay|onRelay|handleBridgedCall|onMessageReceived)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': '(relayMessage|receiveMessage|finalizeDeposit|finalizeWithdraw|handleMessage|_relay|onRelay|handleBridgedCall|onMessageReceived)'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(messenger|bridge|endpoint|relayer|_messenger|_bridge|_endpoint|canonicalBridge)|xDomainMessageSender\\s*\\(\\s*\\)\\s*==|onlyMessenger|onlyBridge|onlyRelayer|_verifySender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-chain-sender-not-bound-canonical: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
