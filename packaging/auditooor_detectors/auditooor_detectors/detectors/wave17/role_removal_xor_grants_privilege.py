"""
role-removal-xor-grants-privilege — generated from reference/patterns.dsl/role-removal-xor-grants-privilege.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py role-removal-xor-grants-privilege.yaml
Source: code4arena/slice_ac-Blackhole-M04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RoleRemovalXorGrantsPrivilege(AbstractDetector):
    ARGUMENT = "role-removal-xor-grants-privilege"
    HELP = "Role/permission bitmap uses `role ^= flag` to revoke. XOR on an absent flag accidentally grants the flag — turning 'remove role' into 'grant role' for any caller who never had it."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/role-removal-xor-grants-privilege.yaml"
    WIKI_TITLE = "Role removal via XOR flips flag on when absent (grants privilege)"
    WIKI_DESCRIPTION = "Hand-rolled role-bitmap systems sometimes use `user.roleBitmap ^= roleFlag` to revoke a bit. XOR toggles: if the bit is on, it clears; if off, it sets. When the admin calls `removeRole(user, role)` on a user who does not hold that role, the XOR silently grants it. Contrast with `&= ~flag`, which is safe on both cases."
    WIKI_EXPLOIT_SCENARIO = "AccessControl contract stores `userRoles[x]` as a uint. `removeRole(u, ADMIN_FLAG)` is implemented as `userRoles[u] ^= ADMIN_FLAG`. Attacker's user is not an admin. Someone calls `removeRole(attacker, ADMIN_FLAG)` — attacker is now admin. Any `removeRole` caller (possibly themselves if permissionless) lands the attack."
    WIKI_RECOMMENDATION = "Use bitwise-clear `role &= ~flag` for removal and bitwise-OR `role |= flag` for grant. Prefer OpenZeppelin AccessControl's mapping-based representation where toggle semantics are not expressible."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(role|Role|permission|Permission|flag|Flag)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(removeRole|revokeRole|clearRole|unsetFlag|removePermission|setRole)'}, {'function.body_contains_regex': '\\^\\s*=\\s*\\w+|\\w+\\s*\\^\\s*\\w+\\s*;'}, {'function.body_not_contains_regex': '&=\\s*~\\s*\\w+|&\\s*~\\s*\\(?\\s*\\w+\\s*\\)?'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — role-removal-xor-grants-privilege: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
