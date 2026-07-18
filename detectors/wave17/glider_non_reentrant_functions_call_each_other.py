"""
glider-non-reentrant-functions-call-each-other — generated from reference/patterns.dsl/glider-non-reentrant-functions-call-each-other.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-non-reentrant-functions-call-each-other.yaml
Source: glider-query-db/non-reentrant-functions-calling-each-other-causes
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderNonReentrantFunctionsCallEachOther(AbstractDetector):
    ARGUMENT = "glider-non-reentrant-functions-call-each-other"
    HELP = "A `nonReentrant` function calls another `nonReentrant` function via `this.other()`. The second call reverts because the guard is already locked, causing unreachable code paths."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-non-reentrant-functions-call-each-other.yaml"
    WIKI_TITLE = "nonReentrant function externally calls another nonReentrant — always reverts"
    WIKI_DESCRIPTION = "OZ's ReentrancyGuard flips a storage slot on entry and restores on exit. Calling `this.other()` from inside a guarded function re-enters the guard and reverts. Function path becomes permanently unreachable."
    WIKI_EXPLOIT_SCENARIO = "`redeem()` is nonReentrant; it calls `this.claimPending()` which is also nonReentrant. Every `redeem` invocation reverts. Users can't exit via redeem; must use a fallback path."
    WIKI_RECOMMENDATION = "Refactor shared code into an internal helper (no modifier); call that from both external entry points."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'nonReentrant|ReentrancyGuard'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['nonReentrant', 'nonReentrantBefore']}}, {'function.body_contains_regex': 'this\\.\\w+|\\b(this)\\b\\s*\\.\\s*\\w+\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-non-reentrant-functions-call-each-other: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
