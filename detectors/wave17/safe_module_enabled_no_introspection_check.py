"""
safe-module-enabled-no-introspection-check — generated from reference/patterns.dsl/safe-module-enabled-no-introspection-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py safe-module-enabled-no-introspection-check.yaml
Source: auditooor-R75-trailofbits-safe-module-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SafeModuleEnabledNoIntrospectionCheck(AbstractDetector):
    ARGUMENT = "safe-module-enabled-no-introspection-check"
    HELP = "Module/plugin registration writes the module into the enabled set with no ERC-165 interface check, codesize check, or owner/authority introspection — a malicious or upgradable module can later exfiltrate the Safe's assets via execTransactionFromModule."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/safe-module-enabled-no-introspection-check.yaml"
    WIKI_TITLE = "Multi-sig / Safe module enable without introspection"
    WIKI_DESCRIPTION = "Gnosis-Safe-wrapping protocols (Zodiac, Llama, Roles-Module) let a privileged caller attach an arbitrary contract as a 'module' — once attached, the module can execute transactions as the Safe via `execTransactionFromModule`. When the enable-module entry-point writes the module address into the enabled set without (a) asserting the module implements the expected `IModule` interface (ERC-165), (b) "
    WIKI_EXPLOIT_SCENARIO = "A DAO uses a Zodiac-style governance module. An admin key, compromised via phishing, calls `enableModule(attackerContract)`. The enable path only checks `msg.sender == admin` and does `modules[attackerContract] = true`. No ERC-165, no codesize, no cross-pointer check. The attacker contract now has module permissions. The attacker calls `attackerContract.drain()` which internally invokes `safe.exec"
    WIKI_RECOMMENDATION = "In `enableModule`: (1) require `module.code.length > 0` (no EOA or yet-to-be-deployed CREATE2 address), (2) require `IERC165(module).supportsInterface(type(IModule).interfaceId)`, (3) require `IModule(module).avatar() == address(this)` (the module's declared controller is us), (4) add a `moduleEnabl"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)enableModule|addModule|registerModule|setModule'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(enableModule|addModule|registerModule|setModule|attachModule)$'}, {'function.writes_storage_matching': '(?i)module|enabled|registered'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyOwners', 'authorized', 'onlySafe', 'selfAuthorized'], 'negate': False}}, {'function.body_not_contains_regex': '(?i)supportsInterface|IERC165|extcodesize|\\.code\\.length|codehash|module\\.owner\\s*\\(|IModule\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — safe-module-enabled-no-introspection-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
