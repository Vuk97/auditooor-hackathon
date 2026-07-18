"""
a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix — generated from reference/patterns.dsl/a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ABuyerOfAGoldCardCanManipulateRandomnessWonTFix(AbstractDetector):
    ARGUMENT = "a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix"
    HELP = "A buyer of a gold card can manipulate randomness — Won't Fix"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix.yaml"
    WIKI_TITLE = "A buyer of a gold card can manipulate randomness  Won't Fix"
    WIKI_DESCRIPTION = "#### Resolution\n\n\n\nThe client decided not to fix this issue with the following comment:\n\n\n\n> \n> We hereby assume that Horizon will always be willing to mine gold cards even at a loss considering the amount of gold cards that can be created per week is limited. If in practice this becomes a problem,"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #13753: #### Resolution\n\n\n\nThe client decided not to fix this issue with the following comment:\n\n\n\n> \n> We hereby assume that Horizon will always be willing to mine gold cards even at a loss considering the a"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(rngDelay|mineGolds|recommit).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(mineGolds|recommit|rngDelay).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-buyer-of-a-gold-card-can-manipulate-randomness-won-t-fix: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
