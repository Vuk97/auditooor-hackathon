"""
test-inverse-cei — generated from reference/patterns.dsl/test-inverse-cei.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py test-inverse-cei.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TestInverseCei(AbstractDetector):
    ARGUMENT = "test-inverse-cei"
    HELP = "Inverted CEI: state mutation BEFORE external call without reentrancy guard."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/test-inverse-cei.yaml"
    WIKI_TITLE = "Inverse-CEI pattern (state write before external call)"
    WIKI_DESCRIPTION = "Function writes storage before making an external call and lacks a reentrancy guard. On protocols whose architecture requires this ordering (optimistic state), set inverse_cei_architecture in .skill_state.yaml to suppress."
    WIKI_EXPLOIT_SCENARIO = "Attacker callback re-enters mid-call and observes a half-finished optimistic write. Only exploitable where the pre-call write is meant as a final, not optimistic, effect."
    WIKI_RECOMMENDATION = "Either adopt strict CEI (writes after the call) or apply nonReentrant; on inverse-CEI-by-design protocols, suppress via workspace state."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_external_call': True}, {'function.pre_external_call_mutates_state': True}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = True

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
                info = [f, f" — test-inverse-cei: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
