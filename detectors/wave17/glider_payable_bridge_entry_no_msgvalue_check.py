"""
glider-payable-bridge-entry-no-msgvalue-check — generated from reference/patterns.dsl/glider-payable-bridge-entry-no-msgvalue-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-payable-bridge-entry-no-msgvalue-check.yaml
Source: hexens-glider/draining-eth-using-flat-fee-without-msgvalue-check
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPayableBridgeEntryNoMsgvalueCheck(AbstractDetector):
    ARGUMENT = "glider-payable-bridge-entry-no-msgvalue-check"
    HELP = "Payable bridge-style entry point (`initiateTransfer`, `crossChainTransfer`, etc.) forwards ETH in a low-level call without requiring `msg.value` covers the forwarded amount. Attacker supplies 0 value, drains the contract's balance via the bridge fee-forwarding path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-payable-bridge-entry-no-msgvalue-check.yaml"
    WIKI_TITLE = "Payable bridge entry drains contract balance — no msg.value require"
    WIKI_DESCRIPTION = "A payable entry point that sends ETH (relayer fee, destination value) MUST assert `msg.value >= forwardedAmount + fee`. Without this, an attacker calls with `msg.value=0` and the contract's own ETH balance funds the forwarded call, permanently leaking into relayer/dest addresses."
    WIKI_EXPLOIT_SCENARIO = "`initiateTransferWithFee(to, amount)` sends `amount` to the relayer and `fee` to the bridge ops. Contract holds 10 ETH from a prior deposit. Attacker calls `initiateTransferWithFee(attacker, 5 ether)` with msg.value=0 — 5 ETH flows to attacker + fee to ops, no new ETH entered the contract."
    WIKI_RECOMMENDATION = "Add `require(msg.value == amount + fee, \"bad msg.value\")` at the top of the entry. If the contract legitimately holds user-ETH (vault model), gate on the caller's accounted balance rather than the contract's native balance."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'initiateTransfer|submitTransfer|crossChainTransfer|bridge'}]
    _MATCH = [{'function.name_matches': '^(initiateTransfer|initiateTransferWithFee|submitTransfer|crossChainTransfer|bridge|sendCrossChain|sendToL1|sendToL2)$'}, {'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\{\\s*value\\s*:|\\.transfer\\s*\\(|\\.send\\s*\\(|\\.sendValue\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.value|assert\\s*\\(\\s*msg\\.value|if\\s*\\(\\s*msg\\.value\\s*(<|!=|==)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-payable-bridge-entry-no-msgvalue-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
