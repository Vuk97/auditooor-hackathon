"""
glider-relayers-can-spoof-messages — generated from reference/patterns.dsl/glider-relayers-can-spoof-messages.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-relayers-can-spoof-messages.yaml
Source: glider-query-db/relayers-can-spoof-messages
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderRelayersCanSpoofMessages(AbstractDetector):
    ARGUMENT = "glider-relayers-can-spoof-messages"
    HELP = "Cross-chain message receiver (`lzReceive`, `handle`, `receiveMessage`) lacks a whitelist check on `msg.sender`. Anyone can craft a fake inbound message."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-relayers-can-spoof-messages.yaml"
    WIKI_TITLE = "Message-receive endpoint lacks relayer authentication"
    WIKI_DESCRIPTION = "Bridge receivers must gate on the trusted endpoint/mailbox. Without that check, any EOA can forge an inbound cross-chain message and trigger the protocol's settle/mint/withdraw path."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls `lzReceive(SOURCE_CHAIN, abi.encode(user, amount), ...)` directly. Contract mints `amount` tokens to `user` (set to attacker-controlled). Bridge drained."
    WIKI_RECOMMENDATION = "`require(msg.sender == trustedEndpoint)` as the first statement of every cross-chain receiver."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'relayer|relay|messaging|_receive|lzReceive|handle\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(lzReceive|handle|receiveMessage|_receiveMessage|relay|onMessage)$'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(trusted|_endpoint|endpoint|mailbox|_mailbox|_gateway|gateway)|onlyRelayer|_checkRelayer|authorizedRelayers\\s*\\[\\s*msg\\.sender\\s*\\]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-relayers-can-spoof-messages: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
