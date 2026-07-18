"""
a-malicious-settings-contract-can-call-onownershiptransferred-to - generated from reference/patterns.dsl/a-malicious-settings-contract-can-call-onownershiptransferred-to.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-settings-contract-can-call-onownershiptransferred-to.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousSettingsContractCanCallOnownershiptransferredTo(AbstractDetector):
    ARGUMENT = "a-malicious-settings-contract-can-call-onownershiptransferred-to"
    HELP = "A malicious settings contract can call onOwnershipTransferred() to take over pair"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-settings-contract-can-call-onownershiptransferred-to.yaml"
    WIKI_TITLE = "A malicious settings contract can call onOwnershipTransferred() to take over pair"
    WIKI_DESCRIPTION = "The function `onOwnershipTransferred()` can be called from a pair via `call()`. This can be done either before `transferOwnership()` or after it. If it is called before `transferOwnership()`, the settings contract can take over the pair."
    WIKI_EXPLOIT_SCENARIO = "A malicious settings contract can call onOwnershipTransferred() to take over pair"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches_regex': '(?i)^remove(.*)$'}, {'function.has_paired_function': {'partner_regex': '(?i)^add\\1$', 'partner_writes_state_var_matching': '.*(call|onOwnershipTransferred|transferOwnership).*', 'negate': False}}, {'function.not_writes_state_var_matching': '.*(call|onOwnershipTransferred|transferOwnership).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" - a-malicious-settings-contract-can-call-onownershiptransferred-to: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
