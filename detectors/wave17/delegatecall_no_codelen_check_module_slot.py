"""
delegatecall-no-codelen-check-module-slot — generated from reference/patterns.dsl/delegatecall-no-codelen-check-module-slot.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegatecall-no-codelen-check-module-slot.yaml
Source: auditooor-R78-polymarket-ProxyFactory
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegatecallNoCodelenCheckModuleSlot(AbstractDetector):
    ARGUMENT = "delegatecall-no-codelen-check-module-slot"
    HELP = "delegatecall to an address read from a module/implementation slot with no code-length check. Zero-code targets (unset, self-destructed, EIP-7702-revoked) return success with empty data — silent no-op."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegatecall-no-codelen-check-module-slot.yaml"
    WIKI_TITLE = "delegatecall to module slot without code-length check — zero-code target silently succeeds"
    WIKI_DESCRIPTION = "When a contract `delegatecall`s into an address read from a storage slot (e.g., `getGSNModule()`, `getImplementation()`, `moduleRegistry.resolve(...)`) without first checking `target.code.length > 0`, a zero-code target produces `success=true` with empty returndata. If the caller then `abi.decode`s the empty bytes, it reverts with a cryptic error. If the caller doesn't decode, the function returns"
    WIKI_EXPLOIT_SCENARIO = "An admin mis-configures the GSN module slot to `address(0)` (or a self-destructed contract). The delegatecall-pattern factory's `_preRelayedCall` / `_postRelayedCall` return success with empty data. GSN relayer charges the user for a relay that did no work; accounting/fee records are silently skipped. Over time, relayed-tx accounting drifts from reality. Worst case: admin re-points to a compromise"
    WIKI_RECOMMENDATION = "Add a `require(module.code.length > 0, ModuleMissing())` at the setter AND at each delegatecall site. The setter-side check catches configuration typos at setup time; the call-site check catches post-deploy state changes (self-destruct, 7702 revocation)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)delegatecall|GSN|module'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': '(?i)\\w+\\.delegatecall\\s*\\('}, {'function.body_not_contains_regex': '(?i)(\\.code\\.length\\s*>\\s*0|extcodesize\\s*\\(\\s*\\w+\\s*\\)\\s*>\\s*0|require\\s*\\(\\s*\\w+\\.code\\.length)'}, {'function.body_contains_regex': '(?i)(get\\w*Module|get\\w*Implementation|\\w+\\.getAddress|\\w+Lib\\.)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegatecall-no-codelen-check-module-slot: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
