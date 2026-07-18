"""
wormhole-uninitialized-implementation-selfdestructable — generated from reference/patterns.dsl/wormhole-uninitialized-implementation-selfdestructable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py wormhole-uninitialized-implementation-selfdestructable.yaml
Source: auditooor-R76-immunefi-wormhole-$10M
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WormholeUninitializedImplementationSelfdestructable(AbstractDetector):
    ARGUMENT = "wormhole-uninitialized-implementation-selfdestructable"
    HELP = "Implementation contract's initialize() is callable on the implementation itself because the constructor does not call _disableInitializers(). An attacker can hijack owner/guardian state on the implementation and then delegatecall SELFDESTRUCT to brick all proxies."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/wormhole-uninitialized-implementation-selfdestructable.yaml"
    WIKI_TITLE = "UUPS implementation left uninitialized, allowing guardian hijack + SELFDESTRUCT"
    WIKI_DESCRIPTION = "A UUPS proxy deploys an implementation whose constructor does not call _disableInitializers() (or set an equivalent sentinel). Because storage on the implementation is separate from the proxy's storage, initialize() on the implementation address is still callable by anyone. An attacker calls it, becomes owner/guardian/relayer, then submits an upgrade whose payload delegatecalls into a contract con"
    WIKI_EXPLOIT_SCENARIO = "Wormhole's implementation at 0x736d2a... had its original initialization reverted by a prior bugfix. An attacker could call initialize() to set attacker-controlled guardians, sign a submitContractUpgrade pointing at a tiny SELFDESTRUCT helper, and delegatecall it — destroying the implementation. The whitehat disclosed this privately and earned the $10M cap."
    WIKI_RECOMMENDATION = "Every UUPS/beacon implementation MUST call `_disableInitializers()` in its constructor. Additionally, in initialize(), use the `initializer` modifier from OZ Initializable and consider `onlyProxy` guards on upgrade entrypoints. Deploy a canary test that calls initialize() directly on the implementat"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^initialize$|^init$|^__\\w+_init$'}, {'function.has_modifier_not': 'initializer|onlyProxy|disableInitializers'}, {'contract.is_upgradeable_impl': True}, {'contract.constructor_not_calls_regex': '(?i)_disableInitializers|_initialized\\s*=\\s*(?:type\\(uint8\\)\\.max|255|true)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — wormhole-uninitialized-implementation-selfdestructable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
