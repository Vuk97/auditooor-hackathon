"""
admin-self-grant-privileged-role — generated from reference/patterns.dsl/admin-self-grant-privileged-role.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py admin-self-grant-privileged-role.yaml
Source: solodit-novel/slice_ae-HyperbeatPay
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdminSelfGrantPrivilegedRole(AbstractDetector):
    ARGUMENT = "admin-self-grant-privileged-role"
    HELP = "Contract grants DEFAULT_ADMIN_ROLE to the owner in initializer, and also grants a privileged OPERATOR/KEEPER/MANAGER/MINTER role — but never calls setRoleAdmin to separate them. Since DEFAULT_ADMIN_ROLE is the admin of every other role, the owner can self-grant the operator role at any time, breakin"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/admin-self-grant-privileged-role.yaml"
    WIKI_TITLE = "DEFAULT_ADMIN_ROLE can self-grant privileged operator role"
    WIKI_DESCRIPTION = "OpenZeppelin AccessControl defaults every role's admin to DEFAULT_ADMIN_ROLE. If a contract grants DEFAULT_ADMIN_ROLE to the deployer/owner without calling `_setRoleAdmin(OPERATOR_ROLE, SOME_OTHER_ROLE)`, the owner can later `grantRole(OPERATOR_ROLE, self)` and call any operator-gated function — nullifying the role separation the protocol advertises."
    WIKI_EXPLOIT_SCENARIO = "Protocol docs say 'owner can upgrade contracts, operator signs off on payouts'. But contract init grants owner DEFAULT_ADMIN_ROLE and never separates OPERATOR_ROLE's admin. Owner self-grants OPERATOR_ROLE and unilaterally drains the payout vault."
    WIKI_RECOMMENDATION = "Call `_setRoleAdmin(OPERATOR_ROLE, OWNER_ROLE)` (or use a timelock role) so DEFAULT_ADMIN_ROLE cannot freely grant privileged operator roles."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'DEFAULT_ADMIN_ROLE|_grantRole|AccessControl'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|__init|setup|initializeV\\d+)'}, {'function.body_contains_regex': '_grantRole\\s*\\(\\s*DEFAULT_ADMIN_ROLE|_setupRole\\s*\\(\\s*DEFAULT_ADMIN_ROLE|grantRole\\s*\\(\\s*DEFAULT_ADMIN_ROLE'}, {'function.body_contains_regex': '_grantRole\\s*\\(\\s*(OPERATOR_ROLE|KEEPER_ROLE|MANAGER_ROLE|MINTER_ROLE|PAUSER_ROLE|UPGRADER_ROLE)'}, {'function.body_not_contains_regex': 'setRoleAdmin\\s*\\(\\s*(OPERATOR_ROLE|KEEPER_ROLE|MANAGER_ROLE|MINTER_ROLE|PAUSER_ROLE|UPGRADER_ROLE)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — admin-self-grant-privileged-role: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
