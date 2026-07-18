"""
operator-management-missing-access-control — generated from reference/patterns.dsl/operator-management-missing-access-control.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py operator-management-missing-access-control.yaml
Source: solodit/Zokyo-EqiFi-2021-05-21
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OperatorManagementMissingAccessControl(AbstractDetector):
    ARGUMENT = "operator-management-missing-access-control"
    HELP = "Privileged operator/role-management functions (addOperator, removeOperator, grantRole, etc.) are callable by anyone because they lack an access-control modifier."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/operator-management-missing-access-control.yaml"
    WIKI_TITLE = "Operator-management functions missing access control"
    WIKI_DESCRIPTION = "Contracts that define an onlyOwner or similar access-control system should protect privileged operator/role-management functions. When these functions are declared external/public without an auth modifier (and without an inline require check), any address can add or remove operators, effectively hijacking administrative control."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls addOperator(attackerAddress) on a token contract. Now attackerAddress is a recognized operator and can mint, burn, or transfer tokens at will. The legitimate owner has no way to revoke the rogue operator except by deploying a patched contract."
    WIKI_RECOMMENDATION = "Add onlyOwner, onlyRole(DEFAULT_ADMIN_ROLE), or an equivalent access-control modifier to every function that modifies the operator or role set. Verify the modifier is enforced in the function signature, not just inside the body."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\bonlyOwner\\b|\\bonlyAdmin\\b|\\bonlyRole\\b|\\bonlyGovernance\\b|\\bonlyManager\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(addOperator|removeOperator|grantRole|revokeRole|addAdmin|removeAdmin|renounceRole)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'onlyManager', 'auth', 'authorized', 'onlyMinter', 'onlyPauser', 'onlyUpgrader', 'restricted'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(owner|admin|governor|manager)|hasRole\\s*\\(|require\\s*\\(\\s*_?(owner|admin|governor|manager)\\s*==\\s*msg\\.sender|_checkRole\\s*\\(|_checkOwner\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — operator-management-missing-access-control: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
