"""
c4-erc721-decrease-missing-clear — generated from reference/patterns.dsl/c4-erc721-decrease-missing-clear.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-erc721-decrease-missing-clear.yaml
Source: code4arena/slice_aa-benddao
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4Erc721DecreaseMissingClear(AbstractDetector):
    ARGUMENT = "c4-erc721-decrease-missing-clear"
    HELP = "Collateral-decrease/unlock path zeros the collateral amount but leaves `lockerAddr[tokenId]` pointing to the stale locker contract. Subsequent paths mis-route funds to the old locker."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-erc721-decrease-missing-clear.yaml"
    WIKI_TITLE = "Decrease/unlock path does not clear lockerAddr"
    WIKI_DESCRIPTION = "Lending pool tracks (amount, lockerAddr) per collateral tokenId. `erc721Decrease` zeros amount but forgets to clear lockerAddr. A later call that reads lockerAddr (e.g. `_releaseCollateral`) routes to the stale locker and loses the NFT."
    WIKI_EXPLOIT_SCENARIO = "Alice repays and calls decrease. amount=0 but lockerAddr still points to the old (possibly compromised) locker. She re-stakes the same NFT; release-path reads lockerAddr and sends the NFT to the stale locker."
    WIKI_RECOMMENDATION = "Delete or overwrite every stateful field tied to the tokenId in the decrease/unlock path (`delete lockerAddr[id]`, `delete custodyOf[id]`)."

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'lockerAddr|locker|custodyOf|collateralOf'}, {'contract.source_matches_regex': '(?i)(lending|collateral|locker|custody|BendDao|isolate|borrow|repay)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(erc721Decrease|decreaseIsolate|_decrease|unlockCollateral|withdrawCollateral)'}, {'function.body_contains_regex': 'delete\\s+\\w+\\[\\s*\\w+\\s*\\]|\\w+\\[\\s*\\w+\\s*\\]\\s*=\\s*0'}, {'function.body_not_contains_regex': 'lockerAddr\\s*\\[\\s*\\w+\\s*\\]\\s*=\\s*address\\s*\\(\\s*0\\s*\\)|delete\\s+lockerAddr|locker\\[.*\\]\\s*=\\s*address'}, {'function.not_source_matches_regex': '(_clearCollateralSlot|_clearPosition|_releaseAll\\s*\\(|delete\\s+_collateralSlot|_slot\\[\\s*\\w+\\s*\\]\\s*=\\s*CollateralSlot\\s*\\(\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — c4-erc721-decrease-missing-clear: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
