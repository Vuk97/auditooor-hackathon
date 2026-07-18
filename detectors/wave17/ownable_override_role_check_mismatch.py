"""
ownable-override-role-check-mismatch — generated from reference/patterns.dsl/ownable-override-role-check-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ownable-override-role-check-mismatch.yaml
Source: solodit-novel/slice_ah-d3-doma
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OwnableOverrideRoleCheckMismatch(AbstractDetector):
    ARGUMENT = "ownable-override-role-check-mismatch"
    HELP = "Contract overrides owner-check to use AccessControl role membership, but transferOwnership does not also transfer the role. Result: new owner is blocked from privileged fns."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ownable-override-role-check-mismatch.yaml"
    WIKI_TITLE = "Ownership transfer does not synchronize role membership"
    WIKI_DESCRIPTION = "Projects that layer AccessControl on top of Ownable must synchronize ownership transfer with role grants. When `_requireCallerIsOwner` is overridden to check `hasRole(OWNER_ROLE, msg.sender)` but `transferOwnership` only writes the `_owner` slot, the new owner does not receive the role and is locked out."
    WIKI_EXPLOIT_SCENARIO = "Contract overrides `_checkOwner` to `require(hasRole(OWNER_ROLE, msg.sender))`. Initial deployment grants OWNER_ROLE to deployer. Deployer calls `transferOwnership(newOwner)`; `_owner` is updated but `OWNER_ROLE` stays with deployer. Now `owner() == newOwner` but every admin function reverts for newOwner. Worse: the old deployer still satisfies the role check, retaining de facto control after an a"
    WIKI_RECOMMENDATION = "Override `_transferOwnership(newOwner)` to call `_grantRole(OWNER_ROLE, newOwner); _revokeRole(OWNER_ROLE, previousOwner())` alongside the `_owner` slot update. Prefer using only one mechanism (Ownable OR AccessControl) per contract."

    _PRECONDITIONS = [{'contract.inherits_any': ['Ownable', 'OwnableUpgradeable', 'Ownable2Step']}, {'contract.source_matches_regex': 'AccessControl|hasRole|grantRole|OPERATOR_ROLE|DEFAULT_ADMIN_ROLE'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'transferOwnership|_transferOwnership'}, {'function.body_not_contains_regex': 'grantRole|revokeRole|renounceRole|_grantRole'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ownable-override-role-check-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
