"""
glider-pause-function-no-access-control — generated from reference/patterns.dsl/glider-pause-function-no-access-control.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-pause-function-no-access-control.yaml
Source: hexens-glider/pause-functions-lack-access-control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPauseFunctionNoAccessControl(AbstractDetector):
    ARGUMENT = "glider-pause-function-no-access-control"
    HELP = "Public `pause()` / `unpause()` has neither an auth modifier nor a `msg.sender` check. Anyone can pause the protocol (grief DoS) or unpause it (defeating an emergency halt)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-pause-function-no-access-control.yaml"
    WIKI_TITLE = "Public pause / unpause with no access control"
    WIKI_DESCRIPTION = "Pausable contracts rely on an admin to trigger _pause / _unpause. If the wrapper is externally callable without access control, any attacker can (a) pause and DoS the protocol whenever convenient — e.g., to block a competitor's liquidation — or (b) unpause during an emergency that admins are still mitigating, re-exposing users to the live exploit."
    WIKI_EXPLOIT_SCENARIO = "Attacker frontruns a large liquidation by calling `pause()`. Liquidators cannot execute; borrower recovers. Attacker unpauses later with no consequence. Repeat per liquidation cycle to extract fees."
    WIKI_RECOMMENDATION = "Apply `onlyOwner` / `onlyRole(PAUSER_ROLE)` to both pause and unpause. Consider a separate PAUSER role to split the pause authority from treasury ops."

    _PRECONDITIONS = [{'contract.source_matches_regex': '_pause\\s*\\(|_unpause\\s*\\('}]
    _MATCH = [{'function.name_matches': '^(pause|unpause|togglePause)$'}, {'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'onlyGuardian', 'onlyManager', 'onlyMinter', 'restricted', 'auth'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(owner|admin|governor|guardian|pauser|manager)|hasRole\\s*\\(|require\\s*\\(\\s*_?pausers\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-pause-function-no-access-control: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
