"""
cei-violation-strict — generated from reference/patterns.dsl/cei-violation-strict.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cei-violation-strict.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CeiViolationStrict(AbstractDetector):
    ARGUMENT = "cei-violation-strict"
    HELP = "Check-Effects-Interactions violation: state mutation after external call without reentrancy guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cei-violation-strict.yaml"
    WIKI_TITLE = "CEI violation without reentrancy guard"
    WIKI_DESCRIPTION = "Any function that writes state AFTER an external call and lacks a reentrancy guard is a classic reentrancy candidate. Widest applicability of any pattern in the corpus."
    WIKI_EXPLOIT_SCENARIO = "Attacker's contract re-enters during the external call and observes mid-update state, potentially triggering double-spend, double-mint, or state-corruption."
    WIKI_RECOMMENDATION = "Reorder to CEI (state writes before external calls) OR apply nonReentrant from OpenZeppelin."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_external_call': True}, {'function.post_external_call_mutates_state': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — cei-violation-strict: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
