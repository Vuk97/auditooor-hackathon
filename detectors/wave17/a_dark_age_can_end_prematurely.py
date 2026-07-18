"""
a-dark-age-can-end-prematurely — generated from reference/patterns.dsl/a-dark-age-can-end-prematurely.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-dark-age-can-end-prematurely.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ADarkAgeCanEndPrematurely(AbstractDetector):
    ARGUMENT = "a-dark-age-can-end-prematurely"
    HELP = "A Dark Age Can End Prematurely"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-dark-age-can-end-prematurely.yaml"
    WIKI_TITLE = "A Dark Age Can End Prematurely"
    WIKI_DESCRIPTION = "**Update**\nMarked as \"Fixed\" by the client. Addressed in: `7736eb06074e1de55cccebfc2cbf572e892c08bc`. The client provided the following explanation: Uses supply at mint of the last minted token rather than current supply to calculate isDarkAge.\n\n**File(s) affected:**`DoomsdaySettlers.sol`\n\n**Descrip"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #60862: **Update**\nMarked as \"Fixed\" by the client. Addressed in: `7736eb06074e1de55cccebfc2cbf572e892c08bc`. The client provided the following explanation: Uses supply at mint of the last minted token rather"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(isDarkAge|supply).*'}, {'function.writes_state_var_matching_regex': '(?i).*(isDarkAge|supply).*'}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*(isDarkAge|supply)[^)]*\\)|assert\\s*\\([^)]*(isDarkAge|supply)[^)]*\\)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-dark-age-can-end-prematurely: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
