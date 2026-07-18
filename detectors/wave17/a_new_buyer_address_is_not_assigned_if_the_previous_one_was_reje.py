"""
a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje — generated from reference/patterns.dsl/a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ANewBuyerAddressIsNotAssignedIfThePreviousOneWasReje(AbstractDetector):
    ARGUMENT = "a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje"
    HELP = "A new `buyer` address is not assigned if the previous one was rejected"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje.yaml"
    WIKI_TITLE = "A new `buyer` address is not assigned if the previous one was rejected"
    WIKI_DESCRIPTION = "There is an issue where the contract resets the `buyer` address, but the `deposited` variable value remains unchanged. It will prevent the new `buyer` address from properly using the escrow."
    WIKI_EXPLOIT_SCENARIO = "A new `buyer` address is not assigned if the previous one was rejected"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(buyer|deposited).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(buyer|deposited).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-new-buyer-address-is-not-assigned-if-the-previous-one-was-reje: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
