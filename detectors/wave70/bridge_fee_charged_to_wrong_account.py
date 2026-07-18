"""
bridge-fee-charged-to-wrong-account — generated from reference/patterns.dsl/bridge-fee-charged-to-wrong-account.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bridge-fee-charged-to-wrong-account.yaml
Source: auditooor-R73-fixdiff-mined-gmx-synthetics-46ae0c843c-sibling-batch6
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BridgeFeeChargedToWrongAccount(AbstractDetector):
    ARGUMENT = "bridge-fee-charged-to-wrong-account"
    HELP = "Bridge deposit/transfer handler passes receiver as the fee-paying account to the cross-chain bridge call, consuming the recipient's balance instead of the initiator's."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bridge-fee-charged-to-wrong-account.yaml"
    WIKI_TITLE = "Bridge deposit charges cross-chain fee to receiver instead of account"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. Sibling of perp-bridge-out-fee-donation-consumes-recipient-balance. A deposit or transfer handler receives distinct account (fee initiator) and receiver (fund recipient) parameters but calls the bridge-out function with receiver as the fee-paying account. A third party who is the account can force the receiver to pay bridge fees by triggerin"
    WIKI_EXPLOIT_SCENARIO = "An attacker creates a deposit with account=attacker_addr and receiver=victim_addr. The executeDeposit function mints tokens to receiver and calls bridgeOut(receiver, amount, receiver) - using receiver as the fee payer. The bridge out charges fees to victim's multichain balance, which the attacker never had to pay. The attacker gains the bridge action; the victim loses the fee."
    WIKI_RECOMMENDATION = "Always pass account (the fee-paying depositor) as the fee-paying parameter to bridge-out calls, not receiver. Add a guard that returns early or routes fee payment to account when account != receiver. Invariant: receiver's balance should only decrease for actions they explicitly authorized."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(bridgeOut|bridge_out|executeDeposit|executeTransfer|multichainBalance|bridgeFee|crossChainFee)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.source_matches_regex': '\\baddress\\b.*\\b(account|sender|depositor|initiator)\\b.*\\baddress\\b.*\\b(receiver|recipient|to)\\b|\\baddress\\b.*\\b(receiver|recipient|to)\\b.*\\baddress\\b.*\\b(account|sender|depositor|initiator)\\b'}, {'function.body_contains_regex': '(?i)\\b(bridgeOut|bridge_out|bridgeCrossChain|crossChainTransfer|bridgeOutFromController)\\s*\\([^;{}]*\\b(receiver|recipient|to)\\b[^;{}]*,\\s*\\b(receiver|recipient|to)\\b[^;{}]*\\)'}, {'function.body_not_contains_regex': '(?i)\\b(account|sender|depositor|initiator)\\b\\s*!=\\s*\\b(receiver|recipient|to)\\b|\\b(receiver|recipient|to)\\b\\s*!=\\s*\\b(account|sender|depositor|initiator)\\b'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — bridge-fee-charged-to-wrong-account: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
