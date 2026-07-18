"""
two-step-admin-propose-self-removes-role-on-accept — generated from reference/patterns.dsl/two-step-admin-propose-self-removes-role-on-accept.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py two-step-admin-propose-self-removes-role-on-accept.yaml
Source: auditooor-R76-cyfrin-myriad-clob-L1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TwoStepAdminProposeSelfRemovesRoleOnAccept(AbstractDetector):
    ARGUMENT = "two-step-admin-propose-self-removes-role-on-accept"
    HELP = "proposeAdmin(admin) allows self-proposal. acceptAdmin grants then revokes — both on the same address — permanently removing DEFAULT_ADMIN_ROLE and bricking the contract."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/two-step-admin-propose-self-removes-role-on-accept.yaml"
    WIKI_TITLE = "Two-step admin handoff: self-proposal + grant/revoke-same-address permanently bricks role"
    WIKI_DESCRIPTION = "A two-step admin transfer mechanism: `proposeAdmin(newAdmin)` stores `pendingAdmin = newAdmin`; `acceptAdmin()` issues `_grantRole(DEFAULT_ADMIN_ROLE, pendingAdmin)` then `_revokeRole(DEFAULT_ADMIN_ROLE, oldAdmin)`. If an admin mistakenly or maliciously calls `proposeAdmin(admin_self)`, the grant is a no-op (role already held) and the revoke strips the role. `hasRole(DEFAULT_ADMIN_ROLE, *)` return"
    WIKI_EXPLOIT_SCENARIO = "Admin tests the two-step flow by proposing their own address as a sanity check: `proposeAdmin(admin)` → `acceptAdmin()`. State: pendingAdmin was admin; `_grantRole(admin)` no-op; `_revokeRole(admin)` executes; now `hasRole(DEFAULT_ADMIN_ROLE, admin) == false`. Admin attempts any follow-up action — `upgradeTo`, `grantRole`, `setTreasury` — all revert on the admin check. Protocol is unmanageable; th"
    WIKI_RECOMMENDATION = "Add `require(newAdmin != admin, 'cannot self-propose')` in proposeAdmin. Even better: in acceptAdmin do `if (newAdmin != oldAdmin) { revoke(oldAdmin) }`, and/or store the admin as a single state variable (not both a role AND a state var) to prevent split-brain states. Forbid admin from being the zer"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)AccessControl|AdminRegistry|AdminRegistry|OwnableUpgradeable'}, {'contract.has_function_matching': '(?i)proposeAdmin|transferAdmin|nominateOwner'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)proposeAdmin|nominateAdmin|proposeOwner|transferOwnership|transferAdmin'}, {'function.body_contains_regex': '(?i)pendingAdmin\\s*=|_pendingOwner\\s*='}, {'function.body_not_contains_regex': '(?i)newAdmin\\s*!=\\s*admin|newOwner\\s*!=\\s*owner|newAdmin\\s*!=\\s*msg\\.sender|cannot self-propose|SELF_PROPOSE'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — two-step-admin-propose-self-removes-role-on-accept: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
