"""
self-admin-grant-privilege-escalation — generated from reference/patterns.dsl/self-admin-grant-privilege-escalation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py self-admin-grant-privilege-escalation.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfAdminGrantPrivilegeEscalation(AbstractDetector):
    ARGUMENT = "self-admin-grant-privilege-escalation"
    HELP = "Admin-gated grantRole/addAdmin/setAdmin/promote allows the caller to add a second admin (including themselves) without revoking the caller's own admin role, breaking any 'single admin' invariant other functions rely on."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/self-admin-grant-privilege-escalation.yaml"
    WIKI_TITLE = "Self-admin grant without revoke creates multi-admin privilege escalation"
    WIKI_DESCRIPTION = "The contract exposes an onlyOwner / onlyAdmin entry-point named in the grantRole/addAdmin/setAdmin/promote/addGuardian family that takes an address parameter and writes it into the admin mapping/set. The fix idiom — calling revokeRole / removeAdmin / delete admin on the caller as part of the same transaction — is missing, so the caller ends up as one of multiple admins. Any function elsewhere in t"
    WIKI_EXPLOIT_SCENARIO = "A governance contract exposes `function addAdmin(address a) external onlyAdmin { admins[a] = true; }`. The current admin (compromised or malicious) calls addAdmin(attacker). `admins[attacker]` is now true and `admins[owner]` is still true. The attacker then calls any onlyAdmin-gated function — setFeeRecipient, rescueTokens, upgradeTo — and drains the protocol. If the contract assumed a single admi"
    WIKI_RECOMMENDATION = "Every admin-grant path must either (a) revoke the caller's own role in the same transaction (two-step handover: nominate → accept, then revoke), or (b) use OpenZeppelin's AccessControlDefaultAdminRules which enforces a single DEFAULT_ADMIN_ROLE and a mandatory delay on transfers. If multiple admins "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'admin|adminRole|owners|roles'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'grantRole|_grantRole|addAdmin|setAdmin|promote|addGuardian'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.has_param_of_type': 'address'}, {'function.body_not_contains_regex': '_revokeRole|revokeRole|removeAdmin|delete\\s+admin|\\.remove\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — self-admin-grant-privilege-escalation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
