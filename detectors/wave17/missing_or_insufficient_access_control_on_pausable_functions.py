"""
missing-or-insufficient-access-control-on-pausable-functions — generated from reference/patterns.dsl/missing-or-insufficient-access-control-on-pausable-functions.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-or-insufficient-access-control-on-pausable-functions.yaml
Source: hexens-glider/pause-functions-lack-access-control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingOrInsufficientAccessControlOnPausableFunctions(AbstractDetector):
    ARGUMENT = "missing-or-insufficient-access-control-on-pausable-functions"
    HELP = "Public pause/unpause wrappers visibly lack access control."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-or-insufficient-access-control-on-pausable-functions.yaml"
    WIKI_TITLE = "Missing or insufficient access control on pausable functions"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only that the owned fixture pair separates externally callable pause-state wrappers with no visible auth from a local `onlyOwner` rewrite. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "An attacker calls an unprotected `pause()` wrapper to grief the protocol into downtime, or calls an unprotected `unpause()` wrapper while operators are still handling an incident."
    WIKI_RECOMMENDATION = "Protect pause-state wrappers with `onlyOwner`, `onlyRole(PAUSER_ROLE)`, or an equivalent inline authorization check, and keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(_pause\\s*\\(|_unpause\\s*\\(|whenNotPaused|whenPaused)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(pause|unpause|emergencyPause|togglePause)$'}, {'function.body_contains_regex': '(?i)(_pause\\s*\\(|_unpause\\s*\\(|\\bpaused\\s*=)'}, {'function.not_source_matches_regex': '(?i)\\bonlyOwner\\b|\\bonlyRole\\b|\\bonlyPauser\\b|\\bonlyAdmin\\b|\\brestricted\\b|\\bauth\\b'}, {'function.body_not_contains_regex': '(?i)msg\\.sender\\s*==\\s*(owner|admin|governor|guardian|pauser|manager)|hasRole\\s*\\(|_checkRole\\s*\\(|_checkOwner\\s*\\(|require\\s*\\(\\s*_?pausers\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — missing-or-insufficient-access-control-on-pausable-functions: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
