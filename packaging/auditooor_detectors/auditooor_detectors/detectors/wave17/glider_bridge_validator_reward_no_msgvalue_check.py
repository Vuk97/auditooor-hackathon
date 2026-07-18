"""
glider-bridge-validator-reward-no-msgvalue-check — generated from reference/patterns.dsl/glider-bridge-validator-reward-no-msgvalue-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-bridge-validator-reward-no-msgvalue-check.yaml
Source: glider-docs/dvbridge-flat-fee-validator-reward-no-msgvalue-check
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderBridgeValidatorRewardNoMsgvalueCheck(AbstractDetector):
    ARGUMENT = "glider-bridge-validator-reward-no-msgvalue-check"
    HELP = "Payable bridge entry pays a flat validator fee from contract funds on every call but does not assert `msg.value >= flat_fee`. An attacker supplies 1 wei, triggers the reward payout (which spends the bridge's own ETH balance), and slowly drains the bridge."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-bridge-validator-reward-no-msgvalue-check.yaml"
    WIKI_TITLE = "Bridge pays flat validator fee without checking msg.value"
    WIKI_DESCRIPTION = "Several DvBridge-style bridge contracts expose a payable `initiateTransfer` that, on every call, routes a fixed `validator_fee` of native ETH to registered validators via `rewardValidators(fee)`. If the entry function does not require `msg.value >= validator_fee`, the reward payout is funded not by the caller but by the bridge's own ETH balance — the caller can supply 1 wei and still trigger the p"
    WIKI_EXPLOIT_SCENARIO = "DvBridge has `validator_fee = 0.01 ether`, 4 validators, and 10 ETH in native-asset balance. Attacker calls `initiateTransfer(attacker, 1 wei, …){value: 1}` (the 1 wei satisfies the `amount > 0` check). Inside, the contract emits the transfer event and calls `rewardValidators(0.01 ether)`. Each validator receives 0.0025 ETH from the bridge's own pool, and 0 wei remainder is sent back to msg.sender"
    WIKI_RECOMMENDATION = "Add `require(msg.value >= validator_fee, 'insufficient fee')` as the first check in every payable bridge entry that calls `rewardValidators`. Also consider switching the validator-reward flow to pull-based claims funded by a per-tx percentage fee rather than a flat fee, or hold fees in an escrow acc"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\b(validators|signers|keepers|relayers)\\b'}, {'contract.has_function_matching': '^(rewardValidators|rewardSigners|rewardKeepers|_distributeFee|_payValidators)$'}, {'contract.has_state_declaration_matching': '(?i)\\b(validator_fee|validatorFee|signer_fee|signerFee|keeper_fee|keeperFee|flat_fee|flatFee|reward_fee|rewardFee)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.body_contains_regex': '\\b(rewardValidators|rewardSigners|rewardKeepers|_distributeFee|_payValidators)\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.value\\s*(?:>=|==|>)\\s*(?:validator_?fee|signer_?fee|keeper_?fee|flat_?fee|reward_?fee|fee\\b)|msg\\.value\\s*(?:>=|==)\\s*(?:validator_?fee|signer_?fee|keeper_?fee|flat_?fee|reward_?fee|fee)\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-bridge-validator-reward-no-msgvalue-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
