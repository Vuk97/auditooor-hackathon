"""
state-update-before-try-catch — generated from reference/patterns.dsl/state-update-before-try-catch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py state-update-before-try-catch.yaml
Source: solodit-novel/slice_aa-Astrolab
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StateUpdateBeforeTryCatch(AbstractDetector):
    ARGUMENT = "state-update-before-try-catch"
    HELP = "State decremented (or written) before a try/catch-wrapped external call. If the call reverts, the try/catch swallows the revert and leaves state permanently wrong (no rollback)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/state-update-before-try-catch.yaml"
    WIKI_TITLE = "State write before try/catch: revert-swallow keeps state inconsistent"
    WIKI_DESCRIPTION = "Solidity try/catch captures the called function's revert without reverting the outer transaction. Any state mutation performed before the try block persists even when the inner call fails. This is a common bug in strategies that decrement pending debt before attempting payout — the revert path eats the failure, and the debt is now permanently understated."
    WIKI_EXPLOIT_SCENARIO = "Protocol's harvest() does `pending -= amount; try vault.collect(amount) returns (...) { ... } catch { /* log */ }`. An attacker forces `collect()` to revert (e.g. via a malicious token hook). The catch swallows the revert, `pending` is now `amount` less than reality, and the user loses that reward."
    WIKI_RECOMMENDATION = "Move state writes to AFTER a successful try block (inside the returns branch), or compensate them inside the catch clause. Prefer CEI with a success assertion over try/catch for debt/accounting updates."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\w+\\s*(-=|=\\s*\\w+\\s*-\\s*|--)\\s*\\S+;\\s*\\n[\\s\\S]{0,120}?try\\s+\\w+'}, {'function.body_not_contains_regex': 'catch\\s*(\\([^\\)]*\\))?\\s*\\{[^}]*(\\+=|=\\s*\\w+\\s*\\+\\s*|\\+\\+)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — state-update-before-try-catch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
