"""
a-misbehaving-validator-can-influence-voting-outcomes-even-after — generated from reference/patterns.dsl/a-misbehaving-validator-can-influence-voting-outcomes-even-after.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-misbehaving-validator-can-influence-voting-outcomes-even-after.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMisbehavingValidatorCanInfluenceVotingOutcomesEvenAfter(AbstractDetector):
    ARGUMENT = "a-misbehaving-validator-can-influence-voting-outcomes-even-after"
    HELP = "A misbehaving validator can influence voting outcomes even after their voting power is reduced to 0"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-misbehaving-validator-can-influence-voting-outcomes-even-after.yaml"
    WIKI_TITLE = "A misbehaving validator can influence voting outcomes even after their voting power is reduced to 0"
    WIKI_DESCRIPTION = "Validators are trusted parties appointed by DAO as a second-level check to prevent malicious proposals from getting executed.\nThe current system is designed with the following constraints:\n1. Executing `GovValidators::changeBalances` is the only way to assign or withdraw voting powe"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #27316: Validators are trusted parties appointed by DAO as a second-level check to prevent malicious proposals from getting executed.\nThe current system is designed with the following constra"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(isValidator|vote|cancelVote|GovValidator).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.reads_state_var_matching': '.*(cancelVote|isValidator|vote).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-misbehaving-validator-can-influence-voting-outcomes-even-after: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
