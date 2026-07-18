"""
uups-missing-disable-initializers — generated from reference/patterns.dsl/uups-missing-disable-initializers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uups-missing-disable-initializers.yaml
Source: solodit-cluster/C0248
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UupsMissingDisableInitializers(AbstractDetector):
    ARGUMENT = "uups-missing-disable-initializers"
    HELP = "UUPS/Initializable implementation exposes initialize() without _disableInitializers() in the constructor — implementation can be initialized by anyone. (inverted Phase 40b)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uups-missing-disable-initializers.yaml"
    WIKI_TITLE = "Missing _disableInitializers in upgradeable implementation constructor"
    WIKI_DESCRIPTION = "OpenZeppelin's Initializable pattern requires every upgradeable implementation contract to call _disableInitializers() in its constructor. Without it, the implementation itself (not just the proxy) can be initialized by an attacker, who then becomes owner and can upgrade the proxy or self-destruct the implementation."
    WIKI_EXPLOIT_SCENARIO = "Attacker observes the deployed implementation address, calls initialize() directly on the implementation, becomes owner of the implementation, then (for UUPS) calls upgradeTo() with a malicious implementation that selfdestructs or takes over the proxy via delegatecall semantics."
    WIKI_RECOMMENDATION = "Add a constructor that calls _disableInitializers(): `constructor() { _disableInitializers(); }`. This locks the implementation so only proxies (which have their own storage) can be initialized."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['Initializable', 'UUPSUpgradeable', 'OwnableUpgradeable', 'AccessControlUpgradeable', 'ERC20Upgradeable', 'ERC721Upgradeable', 'ERC1155Upgradeable', 'PausableUpgradeable', 'ReentrancyGuardUpgradeable']}, {'contract.has_no_function_body_matching': '_disableInitializers\\s*\\(\\s*\\)\\s*;'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^initialize([A-Z_].*)?$'}, {'function.has_modifier': {'includes': ['initializer', 'reinitializer'], 'negate': False}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_not_contains_regex': '(?i)mock|test|fixture'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uups-missing-disable-initializers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
