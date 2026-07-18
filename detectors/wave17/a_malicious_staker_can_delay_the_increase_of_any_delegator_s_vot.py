"""
a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot - generated from reference/patterns.dsl/a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousStakerCanDelayTheIncreaseOfAnyDelegatorSVot(AbstractDetector):
    ARGUMENT = "a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot"
    HELP = "A malicious staker can delay the increase of any delegator's voteWeight as much as he wants"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot.yaml"
    WIKI_TITLE = "A malicious staker can delay the increase of any delegator's voteWeight as much as he wants"
    WIKI_DESCRIPTION = "When a staker delegates his balance to a delegator, the time duration variable `_weights[delegate].stakeTime` is decreased. However, when undelegating only the balance is decreased. This makes it possible a malicious user can decrease `_weights[delegate].stakeTime`."
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #33573: A malicious staker can repeatedly delegate and undelegate to manipulate the stakeTime of a delegator, delaying the increase of their voteWeight indefinitely."
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches_regex': '(?i).*(voteWeight|HalfTime|votePower|balance).*'}, {'function.reads_state_var_matching_regex': '(?i).*(balance|setUserVoteDelegate|stake).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.does_not_call_matching_regex': '(?i).*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" - a-malicious-staker-can-delay-the-increase-of-any-delegator-s-vot: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
