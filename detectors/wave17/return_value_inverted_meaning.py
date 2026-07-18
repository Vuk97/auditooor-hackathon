"""
return-value-inverted-meaning — generated from reference/patterns.dsl/return-value-inverted-meaning.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py return-value-inverted-meaning.yaml
Source: solodit-cluster/cross-cluster-return-inversion
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReturnValueInvertedMeaning(AbstractDetector):
    ARGUMENT = "return-value-inverted-meaning"
    HELP = "Predicate-style function (is/has/can/should*) whose boolean return is inverted relative to its name: returns false on success or true on failure, or places the false-return on a success fall-through after a revert branch."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/return-value-inverted-meaning.yaml"
    WIKI_TITLE = "Return value inverted vs. function-name semantics"
    WIKI_DESCRIPTION = "A public/external function whose name implies a boolean outcome (isAllowed, hasRole, canExecute, shouldSettle) mixes revert-style error handling with explicit boolean returns in a way that inverts the expected convention. Callers that read the bool as `true == success` are silently misled when the function actually returns true on the failure branch (or false on the success branch)."
    WIKI_EXPLOIT_SCENARIO = "An access-control hook `isAuthorized(address user)` reverts on a denylisted entry and falls through to `return false` for the positive case. Any integrator that does `require(isAuthorized(user), ...)` will therefore revert on the legitimate user while the attacker path (which reverted early) is never reached by callers that already catch the revert. Alternatively, a `canWithdraw` predicate that re"
    WIKI_RECOMMENDATION = "Align the return sentinel with the function name: predicate-style names should return true on the positive case and false on the negative case, with reverts reserved for truly unrecoverable invariants. Prefer either pure-boolean (no reverts) or pure-revert (no return value) styles — do not mix. Cove"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(is|has|can|should|_is|_has)[A-Z]'}, {'function.body_contains_regex': 'if\\s*\\([^)]+\\)\\s*\\{[^}]*revert[^}]*\\}[^}]*return\\s+false|if\\s*\\([^)]+\\)\\s*\\{[^}]*return\\s+true[^}]*\\}[^}]*revert'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — return-value-inverted-meaning: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
