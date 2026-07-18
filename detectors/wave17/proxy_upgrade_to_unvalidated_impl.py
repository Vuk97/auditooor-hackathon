"""
proxy-upgrade-to-unvalidated-impl — generated from reference/patterns.dsl/proxy-upgrade-to-unvalidated-impl.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py proxy-upgrade-to-unvalidated-impl.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProxyUpgradeToUnvalidatedImpl(AbstractDetector):
    ARGUMENT = "proxy-upgrade-to-unvalidated-impl"
    HELP = "UUPS upgrade entry point is admin-gated but does not validate that `newImpl` implements the required UUPS interface. An admin misconfiguration upgrades the proxy to a non-UUPS implementation and permanently bricks the system."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/proxy-upgrade-to-unvalidated-impl.yaml"
    WIKI_TITLE = "UUPS upgrade without implementation validation"
    WIKI_DESCRIPTION = "`_authorizeUpgrade` / `upgradeTo` / `upgradeToAndCall` check that the caller is an admin but never verify that the incoming implementation address actually exposes the UUPS surface (`proxiableUUID`, `upgradeTo`, or an equivalent ERC-165 `supportsInterface` probe). A single admin action pointing at the wrong address permanently bricks the proxy — no recovery path exists because the broken implement"
    WIKI_EXPLOIT_SCENARIO = "The admin of a live UUPS-proxied vault intends to upgrade to `VaultV2` at address 0xAAAA. A copy-paste error, a phished deploy script, or a compromised multisig signer instead supplies 0xBBBB, which points at an EOA or a legacy non-UUPS contract. `_authorizeUpgrade` only checks `onlyOwner` and the proxy dutifully overwrites its implementation slot. From this moment on every user call fails because"
    WIKI_RECOMMENDATION = "Before writing the new implementation slot, validate the target. At minimum check `newImpl.code.length > 0`. Preferably call `IERC1822(newImpl).proxiableUUID()` and `require(...) == _IMPLEMENTATION_SLOT`, or probe `supportsInterface(type(IUUPSUpgradeable).interfaceId)` via ERC-165. OpenZeppelin's `U"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['UUPSUpgradeable']}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^_authorizeUpgrade$|^upgradeTo$|^upgradeToAndCall$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.has_high_level_call_named': '(?i)^(_upgradeTo|_upgradeToAndCall|_upgradeToAndCallUUPS|_setImplementation|_authorizeUpgrade|upgradeTo|upgradeToAndCall)$'}, {'function.body_not_contains_regex': 'supportsInterface|IUUPSUpgradeable|_validateImpl|newImpl\\.code\\.length|Address\\.isContract|isContract\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — proxy-upgrade-to-unvalidated-impl: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
