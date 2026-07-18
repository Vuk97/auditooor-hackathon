"""
admin-bypass-umbrella - generated from reference/patterns.dsl/admin-bypass-umbrella.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py admin-bypass-umbrella.yaml
Source: hackerman-v2-recall-batch3-2026-05-19
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdminBypassUmbrella(AbstractDetector):
    ARGUMENT = "admin-bypass-umbrella"
    HELP = "Privileged setter, initializer, role grant, admin wrapper, collision-prone signature auth, or force-operation policy-bypass path that mutates privileged or policy-gated state without a same-function authority check."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/admin-bypass-umbrella.yaml"
    WIKI_TITLE = "Admin bypass - privileged mutation or admin wrapper missing access control"
    WIKI_DESCRIPTION = "The contract exposes an external or public function that mutates owner, admin, role, collateral, blacklist-gated position state, whitelist, pause, selector, facet, implementation, oracle, fee, or other privileged configuration state. The same function lacks onlyOwner, onlyAdmin, onlyRole, requiresAuth, initializer, or an equivalent policy check, or it relies on a collision-prone `abi.encodePacked`"
    WIKI_EXPLOIT_SCENARIO = "A DeFi vault exposes `function setFeeRecipient(address r) external { feeRecipient = r; }` with no owner guard. Any user sets feeRecipient to their own address and siphons protocol fees. A settings contract setter without access control lets an attacker inject a callback that fires during ownership transfer. A public `grantRole(OPERATOR_ROLE, msg.sender)` path lets an attacker self-grant a privileg"
    WIKI_RECOMMENDATION = "Add onlyOwner, onlyAdmin, AccessControl.hasRole(ADMIN_ROLE, msg.sender), initializer, or requiresAuth to every entrypoint that mutates privileged state or routes admin calldata. When privileged writes are authorized by signature, hash with `abi.encode` or EIP-712 typed data rather than `abi.encodePa"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(owner|admin|operator|governance|controller|manager|settings|config|collateral|paused|frozen|whitelist|blacklist|role|selector|facet|implementation|delegatecall)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(set|update|enable|disable|configure|register|initialize|init|setup|authorize|permit|approve|setConfig|setSettings|setOwner|setAdmin|setOperator|setController|setManager|transferOwnership|setCollateral|setLimit|setThreshold|setFee|addToken|removeToken|setToken|setOracle|setPrice|setRate|addMarket|removeMarket|enableMarket|disableMarket|setMarket|setPause|pause|unpause|setWhitelist|setBlacklist|addToWhitelist|removeFromWhitelist|grantRole|revokeRole|setRole|addAdmin|removeAdmin|authorizeUpgrade|upgradeTo|upgradeToAndCall|executeAdmin|adminCall|forwardAdmin|routeAdmin|delegateAdmin|dispatchAdmin|executeBatchBypass|executeBypass|applySelector|setSelector|registerSelector|diamondCut|cover|absorb|foreclose|auction|liquidate|seize|forceRepay|forceClose|closePosition|closeLoan).*'}, {'function.body_contains_regex': '(?i)(_owner\\s*=|owner\\s*=|pendingOwner\\s*=|admin\\s*=|_admin\\s*=|governance\\s*=|controller\\s*=|operator\\s*=|manager\\s*=|guardian\\s*=|pauser\\s*=|settings\\s*=|config\\s*=|oracle\\s*=|router\\s*=|implementation\\s*=|feeRecipient\\s*=|treasury\\s*=|maxLimit\\s*=|feeRate\\s*=|paused\\s*=|_paused\\s*=|frozen\\s*=|isAdmin\\s*\\[|admins\\s*\\[|operators\\s*\\[|controllers\\s*\\[|whitelist\\s*\\[|blacklist\\s*\\[|roles\\s*\\[|role\\s*\\[|collateralEnabled\\s*\\[|collateral\\s*\\[|oracle\\w*\\s*\\[|isEnabled\\s*\\[|isAllowed\\s*\\[|selectorToFacet\\s*\\[|facetAddress\\s*\\[|approvedSelector\\s*\\[|allowedSelector\\s*\\[|_grantRole\\s*\\(\\s*(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|OPERATOR_ROLE|KEEPER_ROLE|MANAGER_ROLE|MINTER_ROLE|PAUSER_ROLE|UPGRADER_ROLE)|_setupRole\\s*\\(\\s*(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|OPERATOR_ROLE|KEEPER_ROLE|MANAGER_ROLE|MINTER_ROLE|PAUSER_ROLE|UPGRADER_ROLE)|grantRole\\s*\\(\\s*(DEFAULT_ADMIN_ROLE|ADMIN_ROLE|OPERATOR_ROLE|KEEPER_ROLE|MANAGER_ROLE|MINTER_ROLE|PAUSER_ROLE|UPGRADER_ROLE)|setUsingAsCollateral\\s*\\(|\\.(delegatecall|call)\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^;]{0,240}(msg\\.sender\\s*==\\s*(owner|_owner|admin|_admin|governance|controller|operator|manager|guardian|pauser)|_msgSender\\s*\\(\\s*\\)\\s*==\\s*(owner|_owner|admin|_admin|governance|controller|operator|manager|guardian|pauser)|hasRole\\s*\\(|_checkRole\\s*\\(|isOwner\\s*\\(|isAdmin\\s*\\(|isAuthorized\\s*\\(|authorized\\s*\\[|whitelist\\s*\\[)|if\\s*\\([^;]{0,160}(msg\\.sender|_msgSender\\s*\\(\\s*\\)).{0,80}(owner|admin|governance|controller|operator|manager|guardian|pauser).{0,80}revert|onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|onlyOperator|onlyController|onlyManager|onlyGuardian|onlyPauser|onlyFactory|requiresAuth|\\bauth\\b|restricted|_checkOwner\\s*\\(\\s*\\)|_onlyOwner\\s*\\(\\s*\\)|enforceIsOwner|enforceIsContractOwner|_authorizeDiamond|_authorizeUpgrade|AccessControl\\._checkRole|isBlacklisted|blacklist\\s*\\[|blacklisted\\s*\\[|denyList|denylist|blocklist|banlist|sanction)'}, {'function.not_source_matches_regex': '(?i)\\b(onlyOwner|onlyAdmin|onlyRole|onlyRoles|onlyGovernance|onlyGovernor|onlyOperator|onlyController|onlyManager|onlyGuardian|onlyPauser|onlyFactory|requiresAuth|auth|restricted|initializer|reinitializer|_checkOwner|_checkRole|hasRole|_authorizeUpgrade|_authorizeDiamond|enforceIsContractOwner)\\b|keccak256\\s*\\(\\s*abi\\.encode\\s*\\(|_hashTypedDataV4|toTypedDataHash|TYPEHASH'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|example|demo)\\b'}]

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
                info = [f, f" - admin-bypass-umbrella: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
