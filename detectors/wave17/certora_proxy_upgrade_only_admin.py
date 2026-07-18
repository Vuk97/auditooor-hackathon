"""
certora-proxy-upgrade-only-admin — generated from reference/patterns.dsl/certora-proxy-upgrade-only-admin.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-proxy-upgrade-only-admin.yaml
Source: certora-examples/Upgradeable/onlyAdminCanUpgrade
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraProxyUpgradeOnlyAdmin(AbstractDetector):
    ARGUMENT = "certora-proxy-upgrade-only-admin"
    HELP = "UUPS/upgradeable proxy function lacks an admin guard — Certora `onlyAdminCanUpgrade` invariant violated, any caller can swap the implementation."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-proxy-upgrade-only-admin.yaml"
    WIKI_TITLE = "Upgrade function missing admin guard (implementation swap by anyone)"
    WIKI_DESCRIPTION = "Certora's UUPS spec (reproduced across OpenZeppelin's audits) proves `_authorizeUpgrade` reverts for non-admin. A common foot-gun: an `_authorizeUpgrade(address) internal override {}` body left empty — compiles fine, passes tests, leaves the proxy wide-open. Any EOA can call `upgradeToAndCall(maliciousImpl, initCalldata)` and seize all storage."
    WIKI_EXPLOIT_SCENARIO = "A contract inherits UUPSUpgradeable but the override is `function _authorizeUpgrade(address newImpl) internal override {}` — empty body, no owner check. Attacker deploys `EvilImpl` that drains every ERC20 the proxy ever held, calls `proxy.upgradeToAndCall(evil, abi.encodeCall(EvilImpl.drain, (attacker)))`. Proxy now executes attacker logic on every call."
    WIKI_RECOMMENDATION = "`_authorizeUpgrade` body must contain `onlyOwner` / `_checkRole(UPGRADER_ROLE)` / equivalent, or the function itself must carry the modifier. Prove Certora's `onlyAdminCanUpgrade` rule in CI."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(UUPS|upgradeTo|_authorizeUpgrade|ERC1967|Initializable)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(upgradeTo|upgradeToAndCall|_authorizeUpgrade|setImplementation|_setImplementation|updateImpl|migrate)$'}, {'function.body_not_contains_regex': '(?i)(onlyOwner|onlyAdmin|onlyRole|_checkRole|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(owner|admin|governance)|require\\s*\\(.*hasRole)'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyProxy', 'onlyGovernance'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-proxy-upgrade-only-admin: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
