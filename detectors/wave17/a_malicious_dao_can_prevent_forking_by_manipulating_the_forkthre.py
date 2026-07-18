"""
a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre — generated from reference/patterns.dsl/a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousDaoCanPreventForkingByManipulatingTheForkthre(AbstractDetector):
    ARGUMENT = "a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre"
    HELP = "A malicious DAO can prevent forking by manipulating the forkThresholdBPS value"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre.yaml"
    WIKI_TITLE = "A malicious DAO can prevent forking by manipulating the forkThresholdBPS value"
    WIKI_DESCRIPTION = "While some of the documentation notes that the fork threshold is expected to be 20%, the forkThresholdBPS is a DAO governance controlled value that may be modified via governance. Functions that read this threshold should validate or sync the value through appropriate guard functions to prevent manipulation."
    WIKI_EXPLOIT_SCENARIO = "A malicious DAO can prevent forking by manipulating the forkThresholdBPS value"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(forkThresholdBPS|MAX_FORK_THRESHOLD).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.reads_state_var_matching_regex': '(?i).*(forkThresholdBPS).*'}, {'function.does_not_call_matching_regex': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-dao-can-prevent-forking-by-manipulating-the-forkthre: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
