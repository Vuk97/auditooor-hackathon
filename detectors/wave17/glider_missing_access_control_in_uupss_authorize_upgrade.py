"""
glider-missing-access-control-in-uupss-authorize-upgrade — generated from reference/patterns.dsl/glider-missing-access-control-in-uupss-authorize-upgrade.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-access-control-in-uupss-authorize-upgrade.yaml
Source: hexens-glider/missing-access-control-in-uupss-authorize-upgrade
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingAccessControlInUupssAuthorizeUpgrade(AbstractDetector):
    ARGUMENT = "glider-missing-access-control-in-uupss-authorize-upgrade"
    HELP = "Missing Access Control on _authorizeUpgrade"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-access-control-in-uupss-authorize-upgrade.yaml"
    WIKI_TITLE = "Missing Access Control on _authorizeUpgrade"
    WIKI_DESCRIPTION = "Detects contracts implementing the UUPSUpgradeable pattern without proper access control on the `_authorizeUpgrade(address)` function."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query missing-access-control-in-uupss-authorize-upgrade. Tags: upgradeability, access-control, uups."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)UUPSUpgradeable|proxiableUUID|_authorizeUpgrade'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.name_matches': '^_authorizeUpgrade$'}, {'function.has_modifier': {'negate': True, 'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyGovernor', 'onlyUpgrader', 'onlyRole', 'onlyAuthorized', 'onlyAuth', 'requireAuth', 'requireOwner', 'authorized', 'auth', 'restricted', 'whenAuthorized']}}, {'function.body_not_contains_regex': '(?i)_checkOwner|_checkRole|hasRole\\s*\\(|onlyRole|require\\s*\\([^)]*(owner|admin|governance|role|auth)|revert\\s+\\w*(NotOwner|NotAdmin|Unauthorized|AccessControl|Forbidden|NotAuthorized)|msg\\.sender\\s*==\\s*(owner|admin|governance|_owner|_admin)|owner\\s*\\(\\s*\\)\\s*==\\s*msg\\.sender'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-missing-access-control-in-uupss-authorize-upgrade: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
