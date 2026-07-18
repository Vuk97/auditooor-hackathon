"""
malformed-equate-statement — generated from reference/patterns.dsl/malformed-equate-statement.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py malformed-equate-statement.yaml
Source: Hexens Glider malformed-equate-statement-fails-to-assign-state-c
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MalformedEquateStatement(AbstractDetector):
    ARGUMENT = "malformed-equate-statement"
    HELP = "Setter-like function contains a standalone `stateVar == value;` expression instead of assigning to that state variable."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/malformed-equate-statement.yaml"
    WIKI_TITLE = "Malformed equate statement"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned setter-like fixture where `threshold == newThreshold;` appears as a standalone expression statement and the corresponding state variable is never written in that function. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A setter-like function appears to update protocol state, but its body contains `threshold == newThreshold;` instead of `threshold = newThreshold;`. Callers believe configuration changed even though the state write never occurs."
    WIKI_RECOMMENDATION = "Replace the malformed equality expression with an assignment and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = []
    _MATCH = [{'function.name_matches': '^(?i)(set|update|configure|assign|change|record|mark)'}, {'function.source_contains': 'threshold == newThreshold;'}, {'function.source_not_contains': 'threshold = newThreshold;'}]

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
                info = [f, f" — malformed-equate-statement: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
