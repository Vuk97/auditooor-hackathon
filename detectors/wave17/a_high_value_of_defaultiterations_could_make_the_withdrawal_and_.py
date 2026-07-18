"""
a-high-value-of-defaultiterations-could-make-the-withdrawal-and- — generated from reference/patterns.dsl/a-high-value-of-defaultiterations-could-make-the-withdrawal-and-.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-high-value-of-defaultiterations-could-make-the-withdrawal-and-.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AHighValueOfDefaultiterationsCouldMakeTheWithdrawalAnd(AbstractDetector):
    ARGUMENT = "a-high-value-of-defaultiterations-could-make-the-withdrawal-and-"
    HELP = "A high value of _defaultIterations could make the withdrawal and repay operations revert because of OOG"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-high-value-of-defaultiterations-could-make-the-withdrawal-and-.yaml"
    WIKI_TITLE = "A high value of _defaultIterations could make the withdrawal and repay operations revert because of OOG"
    WIKI_DESCRIPTION = "## Severity: Medium Risk\n\n## Context\n- PositionsManager.sol#L146-L147\n- PositionsManager.sol#L176-L178\n- MatchingEngine.sol#L128-L158\n\n## Description\nWhen the user executes some actions, they can specify their own `maxIterations` parameter. The user `maxIterations` parameter is directly used in `sup"
    WIKI_EXPLOIT_SCENARIO = "A high value of _defaultIterations could make the withdrawal and repay operations revert because of OOG"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(supply|borrow|withdraw|repay|supplyLogic|borrowLogic|withdrawLogic|repayLogic).*'}, {'function.reads_state_var_matching': '.*(_?defaultIterations|maxIterations|borrowLogic|repayLogic).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_not_contains_regex': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-high-value-of-defaultiterations-could-make-the-withdrawal-and-: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
