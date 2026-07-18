"""
initialize-front-run-no-disable — generated from reference/patterns.dsl/initialize-front-run-no-disable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py initialize-front-run-no-disable.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InitializeFrontRunNoDisable(AbstractDetector):
    ARGUMENT = "initialize-front-run-no-disable"
    HELP = "Upgradeable contract exposes an unguarded initialize() that writes a privileged role (owner/admin/guardian) and the implementation's constructor never calls _disableInitializers(). An attacker front-runs the proxy's initialization, takes over the implementation, and (for UUPS) upgrades it to a malic"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/initialize-front-run-no-disable.yaml"
    WIKI_TITLE = "Unguarded initialize() with no _disableInitializers — implementation takeover"
    WIKI_DESCRIPTION = "OpenZeppelin's upgradeable contracts require the implementation itself be locked against initialization. This is a layered defense: (1) the `initialize()` function uses the `initializer` / `reinitializer` / `onlyProxy` modifier so it can only run once (or through the proxy), and (2) the implementation's constructor calls `_disableInitializers()` so the implementation contract cannot be initialized"
    WIKI_EXPLOIT_SCENARIO = "1) Team deploys a UUPS implementation contract to Ethereum at block N. The implementation has `initialize(address owner)` with no `initializer` modifier; its constructor is empty. 2) Attacker's mempool watcher sees the CREATE2 / CREATE receipt at block N and broadcasts `impl.initialize(attacker)` at block N+1. 3) `attacker` is now `owner` on the implementation. 4) Attacker immediately calls `impl."
    WIKI_RECOMMENDATION = "Two independent fixes, both required: (a) add the `initializer` modifier to every `initialize`-style function; (b) add `constructor() { _disableInitializers(); }` to the implementation. `_disableInitializers` burns the init slot on the implementation so even an unguarded `initialize()` would revert."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['Initializable', 'UUPSUpgradeable', 'OwnableUpgradeable', 'AccessControlUpgradeable', 'ERC20Upgradeable', 'ERC721Upgradeable', 'ERC1155Upgradeable', 'PausableUpgradeable', 'ReentrancyGuardUpgradeable']}, {'contract.has_no_function_body_matching': '_disableInitializers'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|_initialize|init|__init)([A-Za-z0-9_]*)?$'}, {'function.has_modifier': {'includes': ['initializer', 'reinitializer', 'onlyProxy'], 'negate': True}}, {'function.writes_storage_matching': 'owner|admin|guardian'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — initialize-front-run-no-disable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
