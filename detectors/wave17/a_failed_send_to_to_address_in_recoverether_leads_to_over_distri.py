"""
a-failed-send-to-to-address-in-recoverether-leads-to-over-distri — generated from reference/patterns.dsl/a-failed-send-to-to-address-in-recoverether-leads-to-over-distri.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-failed-send-to-to-address-in-recoverether-leads-to-over-distri.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AFailedSendToToAddressInRecoveretherLeadsToOverDistri(AbstractDetector):
    ARGUMENT = "a-failed-send-to-to-address-in-recoverether-leads-to-over-distri"
    HELP = "A failed send to `to` address in `recoverEther` leads to over-distribution to non-failing parties"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-failed-send-to-to-address-in-recoverether-leads-to-over-distri.yaml"
    WIKI_TITLE = "A failed send to `to` address in `recoverEther` leads to over-distribution to non-failing parties"
    WIKI_DESCRIPTION = "https://github.com/p2p-org/eth-staking-fee-distributor-contracts/blob/30a7ff78e8285f2eae4ae552efb390aa4453a083/contracts/feeDistributor/ContractWcFeeDistributor.sol#L193\nhttps://github.com/p2p-org/eth-staking-fee-distributor-contracts/blob/30a7ff78e8285f2eae4ae552efb390aa4453a083/c"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #35049: ##### Description\nhttps://github.com/p2p-org/eth-staking-fee-distributor-contracts/blob/30a7ff78e8285f2eae4ae552efb390aa4453a083/contracts/feeDistributor/ContractWcFeeDistributor.sol#L193\nhttps://gith"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(owner|recoverEther|medium).*'}, {'function.reads_state_var_matching_regex': '(?i).*(medium|owner|recoverEther).*'}, {'function.calls_function_matching': {'regex': '(?i).*(accrue|update|sync|validate|check|refresh).*', 'negate': True}}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-failed-send-to-to-address-in-recoverether-leads-to-over-distri: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
