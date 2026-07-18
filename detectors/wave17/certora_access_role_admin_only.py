"""
certora-access-role-admin-only — generated from reference/patterns.dsl/certora-access-role-admin-only.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-access-role-admin-only.yaml
Source: certora-examples/AccessControl/onlyAdminCanGrant
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAccessRoleAdminOnly(AbstractDetector):
    ARGUMENT = "certora-access-role-admin-only"
    HELP = "Role-granting helper has no admin / onlyRole guard — Certora `onlyAdminCanGrant` invariant violated; anyone can self-promote."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-access-role-admin-only.yaml"
    WIKI_TITLE = "Role grant helper is callable by anyone (self-promotion)"
    WIKI_DESCRIPTION = "Certora's AccessControl spec proves `grantRole(role, x)` is rejected unless the caller holds `getRoleAdmin(role)`. A convenience method (batchGrant, promote, enableRole, _grantRole without `internal` visibility) that writes `_roles[role].members[x] = true` or similar without re-running the admin check lets anyone take over the protocol: call promote(self, DEFAULT_ADMIN_ROLE) → you are now the admi"
    WIKI_EXPLOIT_SCENARIO = "A patch adds `internalGrant(bytes32 role, address account) public` (accidentally public, meant to be internal), writing the role flag directly. Attacker calls `internalGrant(DEFAULT_ADMIN_ROLE, attacker)`, becomes admin, calls `upgradeToAndCall(badImpl)`, drains vault."
    WIKI_RECOMMENDATION = "All role-writing paths must route through `_grantRole` as `internal` only, and public entrypoints must carry `onlyRole(getRoleAdmin(role))`. Reproduce Certora's `onlyAdminCanGrant` rule on every role-mutating function."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(_roles|roles|hasRole)'}, {'contract.source_matches_regex': '(?i)(AccessControl|grantRole|revokeRole|onlyRole|_grantRole)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^([A-Za-z0-9_]*grant[A-Za-z0-9_]*|[A-Za-z0-9_]*addRole|[A-Za-z0-9_]*setRole|[A-Za-z0-9_]*enableRole|_grantRole|internalGrant|authorize|promote|assign)[A-Za-z0-9_]*'}, {'function.writes_storage_matching': '(?i)(_roles|roles|hasRole|members)'}, {'function.body_not_contains_regex': '(?i)(onlyRole|_checkRole|hasRole\\s*\\(\\s*getRoleAdmin|require\\s*\\([^)]*onlyOwner|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(owner|admin))'}, {'function.has_modifier': {'includes': ['onlyRole', 'onlyOwner', 'onlyAdmin', '_checkRole'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-access-role-admin-only: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
