"""
a-malicious-guardian-can-steal-funds-won-t-fix — generated from reference/patterns.dsl/a-malicious-guardian-can-steal-funds-won-t-fix.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-guardian-can-steal-funds-won-t-fix.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousGuardianCanStealFundsWonTFix(AbstractDetector):
    ARGUMENT = "a-malicious-guardian-can-steal-funds-won-t-fix"
    HELP = "A malicious guardian can steal funds  Won't Fix"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-guardian-can-steal-funds-won-t-fix.yaml"
    WIKI_TITLE = "A malicious guardian can steal funds  Won't Fix"
    WIKI_DESCRIPTION = "#### Resolution\n\n\n\nComment from the client: The etherspot payment system is semi-trusted by design.\n\n\n#### Description\n\n\nA guardian is signing every message that should be submitted as a payment channel update.\nA guardian's two main things to verify are: `blockNumber` and the fact that the `sender`"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #18862: #### Resolution\n\n\n\nComment from the client: The etherspot payment system is semi-trusted by design.\n\n\n#### Description\n\n\nA guardian is signing every message that should be submitted as a payment chann"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(blockNumber).*'}, {'function.reads_state_var_matching_regex': '(?i).*(blockNumber).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.does_not_call_matching_regex': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-guardian-can-steal-funds-won-t-fix: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
