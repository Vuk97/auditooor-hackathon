"""
proxy-storage-gap-missing — generated from reference/patterns.dsl/proxy-storage-gap-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py proxy-storage-gap-missing.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProxyStorageGapMissing(AbstractDetector):
    ARGUMENT = "proxy-storage-gap-missing"
    HELP = "Upgradeable contract declares state without a __gap array — any future parent adding new state variables will collide storage slots on upgrade."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/proxy-storage-gap-missing.yaml"
    WIKI_TITLE = "Missing __gap in upgradeable contract (storage collision on upgrade)"
    WIKI_DESCRIPTION = "OpenZeppelin upgradeable contracts reserve a `uint256[50] private __gap;` array at the end of every base contract so subsequent versions can add state variables without shifting child-contract storage slots. A child contract that omits its own __gap risks permanent storage collision if an ancestor ever appends a new variable: existing mappings and balances get corrupted at upgrade time, often sile"
    WIKI_EXPLOIT_SCENARIO = "V1 of an OZ-upgradeable token ships without a storage gap. V2 of the parent OwnableUpgradeable adds a new `address _pendingOwner;` field, shifting the child's `mapping balances` down one slot. On upgrade, every post-upgrade balances lookup reads from the wrong slot — user balances appear zero or become confused with other variables, and the new pendingOwner slot overlaps user data."
    WIKI_RECOMMENDATION = "Append a storage gap to every upgradeable contract: `uint256[50] private __gap;`. The size (50) is conventional, not mandatory; what matters is reserving contiguous unused slots at the end of each contract's storage layout. Whenever a new state variable is added, subtract one from the gap length."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.inherits_any': ['Initializable', 'UUPSUpgradeable', 'OwnableUpgradeable', 'ERC20Upgradeable', 'ERC721Upgradeable', 'ERC1155Upgradeable', 'AccessControlUpgradeable', 'PausableUpgradeable', 'ReentrancyGuardUpgradeable']}, {'contract.has_no_function_body_matching': '__gap|_gap|storage_slot\\d+'}]
    _MATCH = [{'function.is_constructor': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — proxy-storage-gap-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
