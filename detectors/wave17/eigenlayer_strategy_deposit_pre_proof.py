"""
eigenlayer-strategy-deposit-pre-proof — generated from reference/patterns.dsl/eigenlayer-strategy-deposit-pre-proof.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py eigenlayer-strategy-deposit-pre-proof.yaml
Source: solodit-cluster-EIGEN-PREPROOF
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EigenlayerStrategyDepositPreProof(AbstractDetector):
    ARGUMENT = "eigenlayer-strategy-deposit-pre-proof"
    HELP = "EigenLayer-style operator strategy accepts ETH deposits before the validator's beacon-chain withdrawal credentials have been proven, allowing a front-runner to route future rewards to their own malicious validator."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/eigenlayer-strategy-deposit-pre-proof.yaml"
    WIKI_TITLE = "EigenLayer strategy allows deposit before validator credential proof"
    WIKI_DESCRIPTION = "EigenLayer's security model binds an operator's restaked ETH to a specific validator via a BeaconChainProof of the validator's withdrawalCredentials. Strategies that mint operator shares (or otherwise credit deposits) before that proof has been verified break the binding: the deposit is accounted for, but the beacon-chain side of the pairing has not yet been committed to any particular validator."
    WIKI_EXPLOIT_SCENARIO = "Honest operator calls `deposit{value: 32 ether}` on the strategy. The strategy mints them shares immediately and will only call verifyWithdrawalCredentials later. An attacker front-runs the proof transaction with their own proof pointing at a validator they control that shares the same EigenPod. The strategy's internal accounting still credits the original depositor's shares, but future beacon-cha"
    WIKI_RECOMMENDATION = "Make deposit/stake entry points gated on a beacon-chain proof: either require `_requireProven(validator)` at the top of the deposit function, or split the flow into two phases — `registerValidator(proof)` first, then `deposit` — with the deposit path reverting unless the caller's validator is alread"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'EigenPod|beaconChain|BLSPubkey|withdrawalCredentials'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'deposit|stake|_deposit|stakeETH|depositToStrategy'}, {'function.is_payable': True}, {'function.body_not_contains_regex': 'verifyProof|verifyValidator|verifyWithdrawalCredentials|onlyAfterProof|_requireProven|beaconProof'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — eigenlayer-strategy-deposit-pre-proof: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
