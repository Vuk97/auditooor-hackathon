"""
unchecked-external-return — generated from reference/patterns.dsl/unchecked-external-return.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unchecked-external-return.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UncheckedExternalReturn(AbstractDetector):
    ARGUMENT = "unchecked-external-return"
    HELP = "Low-level .call/.send/.delegatecall without checking the boolean return value."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unchecked-external-return.yaml"
    WIKI_TITLE = "Unchecked external call return value"
    WIKI_DESCRIPTION = "Low-level external calls (call/send/delegatecall/staticcall) return a boolean success flag. Ignoring it means a failed call silently succeeds at the Solidity level, violating invariants."
    WIKI_EXPLOIT_SCENARIO = "A failed external call returns false but execution continues as if it succeeded; state that assumed the call succeeded becomes corrupted."
    WIKI_RECOMMENDATION = "Always check return value: `(bool ok, ) = target.call(data); require(ok, \"call failed\");`"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.(call|delegatecall|staticcall|send)\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(success|ok|result)|assert\\s*\\(\\s*(success|ok|result)|if\\s*\\(\\s*!\\s*(success|ok|result)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — unchecked-external-return: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
