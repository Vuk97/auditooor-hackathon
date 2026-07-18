"""
admin-bypass-wrong-domain-or-missing-guard - generated from reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py admin-bypass-wrong-domain-or-missing-guard.yaml
Source: capability-lift-p1-04-admin-bypass-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdminBypassWrongDomainOrMissingGuard(AbstractDetector):
    ARGUMENT = "admin-bypass-wrong-domain-or-missing-guard"
    HELP = "Privileged setter, registry/config update, role mutation, or upgrade/admin operation is public or external without an effective authority check, or uses a wrong authority domain such as tx.origin or caller-supplied admin context."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/admin-bypass-wrong-domain-or-missing-guard.yaml"
    WIKI_TITLE = "Admin bypass through missing or wrong-domain authority guard"
    WIKI_DESCRIPTION = "Externally reachable code mutates privileged owner, admin, role, registry, market, gateway, adapter, oracle, implementation, or protocol configuration state. The same entrypoint lacks an effective owner, admin, role, governance, or factory binding, or its apparent guard checks the wrong actor or a caller-controlled authority domain. Non-authority checks such as zero-address validation or pause che"
    WIKI_EXPLOIT_SCENARIO = "A registry exposes `setAdapter(bytes32 key, address adapter)` with only `require(adapter != address(0))`; any caller replaces the adapter. A gateway setter checks `tx.origin == owner`, so a phishing contract can relay the call while the owner is origin. A fund function accepts `adminContractAddress` as a parameter, so the attacker supplies an admin contract where they own every role. A proxy cedes"
    WIKI_RECOMMENDATION = "Gate every privileged mutator and admin operation with the canonical authority for that state: `onlyOwner`, `onlyRole`, governance, timelock, or factory binding. Do not use `tx.origin` for privileged authorization. Do not accept the authority domain as an untrusted function parameter; load it from i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(owner|admin|governance|governor|factory|role|registry|market|config|gateway|adapter|router|oracle|implementation|upgrade|proxy|controller|manager|operator|guardian|pauser|settings|blacklist|whitelist)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(set|update|change|configure|register|add|remove|enable|disable|grant|revoke|assign|promote|initialize|init|setup|authorize|upgrade|upgradeTo|upgradeToAndCall|migrate|execute|admin|route|forward|dispatch|create|finalize|mint|redeem|pause|unpause).*'}, {'function.body_contains_regex': '(?is)(owner\\s*=|_owner\\s*=|pendingOwner\\s*=|admin\\s*=|_admin\\s*=|governance\\s*=|governor\\s*=|factory\\s*=|registry\\s*=|market\\w*\\s*=|config\\w*\\s*=|gateway\\s*=|adapter\\s*=|router\\s*=|oracle\\s*=|controller\\s*=|manager\\s*=|operator\\s*=|guardian\\s*=|pauser\\s*=|settings\\s*=|implementation\\s*=|proxy\\s*=|treasury\\s*=|feeRecipient\\s*=|marketConfig\\s*\\[|registry\\s*\\[|markets\\s*\\[|configs\\s*\\[|gateways\\s*\\[|adapters\\s*\\[|routers\\s*\\[|oracles\\s*\\[|controllers\\s*\\[|managers\\s*\\[|operators\\s*\\[|guardians\\s*\\[|whitelist\\s*\\[|blacklist\\s*\\[|roles\\s*\\[|role\\s*\\[|_grantRole\\s*\\(|grantRole\\s*\\(|_revokeRole\\s*\\(|revokeRole\\s*\\(|\\.call\\s*\\(|\\.delegatecall\\s*\\()'}, {'function.body_not_contains_regex': '(?is)(require\\s*\\([^;]{0,260}(msg\\.sender|_msgSender\\s*\\(\\s*\\)).{0,120}(owner|_owner|admin|_admin|governance|governor|factory|controller|manager|operator|guardian|pauser|trustedForwarder)|require\\s*\\([^;]{0,260}(owner|_owner|admin|_admin|governance|governor|factory|controller|manager|operator|guardian|pauser|trustedForwarder).{0,120}(msg\\.sender|_msgSender\\s*\\(\\s*\\))|if\\s*\\([^;]{0,220}(msg\\.sender|_msgSender\\s*\\(\\s*\\)).{0,140}(owner|admin|governance|governor|factory|controller|manager|operator|guardian|pauser).{0,120}revert|hasRole\\s*\\(|_checkRole\\s*\\(|_checkOwner\\s*\\(|_onlyOwner\\s*\\(|isOwner\\s*\\(|isAdmin\\s*\\(|isAuthorized\\s*\\(|authorized\\s*\\[|AccessControl\\._checkRole|enforceIsOwner|enforceIsContractOwner|enforceIsGovernance)'}, {'function.body_not_contains_regex': '(?is)(onlyOwner\\s*\\(|onlyAdmin\\s*\\(|onlyRole\\s*\\(|onlyRoles\\s*\\(|onlyGovernance\\s*\\(|onlyGovernor\\s*\\(|onlyFactory\\s*\\(|onlyController\\s*\\(|onlyManager\\s*\\(|onlyOperator\\s*\\(|onlyGuardian\\s*\\(|requiresAuth\\s*\\(|requireAuth\\s*\\(|auth\\s*\\(|restricted\\s*\\()'}, {'function.has_modifier': {'negate': True, 'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyGovernor', 'onlyFactory', 'onlyController', 'onlyManager', 'onlyOperator', 'onlyGuardian', 'onlyPauser', 'requiresAuth', 'requireAuth', 'auth', 'restricted', 'initializer', 'reinitializer']}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example|demo)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" - admin-bypass-wrong-domain-or-missing-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
