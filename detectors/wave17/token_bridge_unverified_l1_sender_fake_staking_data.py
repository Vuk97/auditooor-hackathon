"""
token-bridge-unverified-l1-sender-fake-staking-data — generated from reference/patterns.dsl/token-bridge-unverified-l1-sender-fake-staking-data.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py token-bridge-unverified-l1-sender-fake-staking-data.yaml
Source: auditooor-R75-c4-yield-2024-05-olas-22
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TokenBridgeUnverifiedL1SenderFakeStakingData(AbstractDetector):
    ARGUMENT = "token-bridge-unverified-l1-sender-fake-staking-data"
    HELP = "onTokenBridged callback forwards bridged payload into staking/dispenser logic without verifying the L1 sender."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/token-bridge-unverified-l1-sender-fake-staking-data.yaml"
    WIKI_TITLE = "L2 token-bridge callback forwards unauthenticated payload into staking incentives dispatcher"
    WIKI_DESCRIPTION = "Token bridges (Omnibridge / Gnosis AMB) let any L1 address send tokens to any L2 contract and trigger a receiver callback. Receivers that forward the callback payload into privileged staking / incentives / governance logic must verify the L1 sender, or an attacker can spoof arbitrary staking instructions. Because the callback carries whatever the L1 caller wrote, it is equivalent to an unauthentic"
    WIKI_EXPLOIT_SCENARIO = "Olas GnosisTargetDispenserL2.onTokenBridged: attacker calls relayTokensAndCall() on L1 Omnibridge, sending 1 wei of any token with a crafted payload that claims 1000 OLAS of staking rewards for an attacker-controlled target. Contract has no l1Sender check — dispenses the rewards or queues them for attacker's target."
    WIKI_RECOMMENDATION = "Route token and instruction separately: tokens via relayTokens (no callback), instructions via the authenticated AMB with `bridgeMessenger.messageSender() == expectedL1Dispatcher`. Remove the onTokenBridged callback entirely, or gate it on a hardcoded L1 sender address extracted from the AMB context"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'contract.name_matches: (?i)(targetDispenser|bridgeReceiver|l2.*receiver|omnibridge.*handler)']
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^onTokenBridged$|^handleTokenBridged$|^bridgedToken$|^onL1MessageReceived$'}, {'function.body_contains_regex': '(?i)_receiveMessage|_processData|_dispatchIncentives|stakingQueueingNonces'}, {'function.not_in_skip_list': True}, "!function.body_contains_regex: '(?i)(messageSender\\s*==|l1Sender|trustedSender|_validateSender|bridgeMessenger\\.l1Sender)'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — token-bridge-unverified-l1-sender-fake-staking-data: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
