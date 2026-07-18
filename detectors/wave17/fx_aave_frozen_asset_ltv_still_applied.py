"""
fx-aave-frozen-asset-ltv-still-applied — generated from reference/patterns.dsl/fx-aave-frozen-asset-ltv-still-applied.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-aave-frozen-asset-ltv-still-applied.yaml
Source: github:aave-dao/aave-v3-origin@d13aef0
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxAaveFrozenAssetLtvStillApplied(AbstractDetector):
    ARGUMENT = "fx-aave-frozen-asset-ltv-still-applied"
    HELP = "When a reserve is frozen, its LTV should be set to zero immediately and the intended LTV stored as pending. The vulnerable code stores the new LTV as pending but still calls setLtv(ltv) with the original non-zero value, allowing frozen reserves to be used as collateral."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-aave-frozen-asset-ltv-still-applied.yaml"
    WIKI_TITLE = "Frozen reserve LTV not zeroed on configureReserveAsCollateral — frozen assets still usable as collateral"
    WIKI_DESCRIPTION = "Pool configurator implementations that separate pending and active LTV for frozen reserves must zero the active LTV when the reserve is frozen and restore it from pending when unfrozen. If setLtv(ltv) is called unconditionally before checking the frozen flag, a freeze operation will store ltv in _pendingLtv but also leave the same ltv in the active configuration, allowing users to continue borrowi"
    WIKI_EXPLOIT_SCENARIO = "Aave v3 Cantina-31 (2024): configureReserveAsCollateral() stores ltv in _pendingLtv when frozen=true but then calls currentConfig.setLtv(ltv) unconditionally. Frozen reserves retain their non-zero LTV, allowing new borrows against them despite the freeze intent."
    WIKI_RECOMMENDATION = "In the frozen branch: call `currentConfig.setLtv(0)` and emit the event with ltv=0. In the unfrozen branch: call `currentConfig.setLtv(_pendingLtv[asset])` and delete the pending entry. Never call setLtv(ltv) unconditionally across both branches."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^configureReserveAsCollateral$|^setAssetAsFrozen$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'configureReserveAsCollateral|setCollateral|setAssetAsFrozen|setFrozen'}, {'function.body_contains_regex': 'getFrozen|isFrozen|_pendingLtv|pendingLtv'}, {'function.body_not_contains_regex': 'setLtv\\(0\\)|setLtv\\(ltv.*0\\)|pendingLtv\\[.*\\]\\s*=\\s*.*getLtv'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-aave-frozen-asset-ltv-still-applied: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
