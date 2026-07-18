"""
glider-pause-functions-lack-access-control — generated from reference/patterns.dsl/glider-pause-functions-lack-access-control.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-pause-functions-lack-access-control.yaml
Source: glider-query-db/pause-functions-lack-access-control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPauseFunctionsLackAccessControl(AbstractDetector):
    ARGUMENT = "glider-pause-functions-lack-access-control"
    HELP = "`pause()` / `unpause()` functions are callable by anyone. A griefer can permanently brick the protocol (pause) or reopen a disabled contract (unpause) at will."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-pause-functions-lack-access-control.yaml"
    WIKI_TITLE = "Pause/unpause functions missing access control"
    WIKI_DESCRIPTION = "Permissionless pause is DoS-as-a-service: any address can halt the protocol at any time. Permissionless unpause defeats the purpose of pause by letting an attacker reactivate a compromised contract."
    WIKI_EXPLOIT_SCENARIO = "Attacker front-runs large withdrawal queue by calling `pause()`, DoS'ing all users until the team investigates and deploys a patch. Total downtime cost: days + trust damage."
    WIKI_RECOMMENDATION = "Add `onlyOwner` / `onlyRole(PAUSER_ROLE)` / `onlyRole(UNPAUSER_ROLE)` to both functions."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Pausable|_pause\\(\\)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(pause|unpause|emergencyPause)$'}, {'function.body_contains_regex': '_pause\\s*\\(|_unpause\\s*\\(|paused\\s*='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==|onlyRole|_checkRole|_checkOwner|hasRole'}, {'function.not_source_matches_regex': '\\bonlyOwner\\b|\\bonlyPauser\\b|\\bonlyAdmin\\b|\\bonlyRole\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-pause-functions-lack-access-control: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
