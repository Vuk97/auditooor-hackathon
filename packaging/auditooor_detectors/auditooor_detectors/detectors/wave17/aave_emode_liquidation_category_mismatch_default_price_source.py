"""
aave-emode-liquidation-category-mismatch-default-price-source — generated from reference/patterns.dsl/aave-emode-liquidation-category-mismatch-default-price-source.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-emode-liquidation-category-mismatch-default-price-source.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-28f72fe824
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveEmodeLiquidationCategoryMismatchDefaultPriceSource(AbstractDetector):
    ARGUMENT = "aave-emode-liquidation-category-mismatch-default-price-source"
    HELP = "eMode category match uses raw `==` on the packed 8-bit category id instead of the canonical isInEModeCategory() helper — fails when the helper's special-case rules (e.g. default/zero category) apply, causing wrong liquidation bonus or price source."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-emode-liquidation-category-mismatch-default-price-source.yaml"
    WIKI_TITLE = "Raw equality check on eMode category bypasses isInEModeCategory semantics in liquidation"
    WIKI_DESCRIPTION = "Aave v3 executeLiquidationCall selects the liquidation bonus and price source for a collateral reserve based on whether that reserve belongs to the user's eMode category. Pre-fix the check was `params.userEModeCategory == collateralReserve.configuration.getEModeCategory()`. EModeLogic defines the richer helper `isInEModeCategory(user, reserve)` that handles the convention that category 0 means 'no"
    WIKI_EXPLOIT_SCENARIO = "A future eMode upgrade stores a category bitmap where '5 stablecoins' category has id=5 and its liquidation logic considers id=7 (a superset) also matching. HF calculation (which uses isInEModeCategory) treats the user's id=7 position as part of the stablecoin eMode and grants the reduced 1.01 bonus. Liquidation path (which uses ==) sees 7 != 5, falls back to the default large bonus (e.g. 1.10) — "
    WIKI_RECOMMENDATION = "Always route eMode matching through `EModeLogic.isInEModeCategory(userCategoryId, reserveCategoryId)` (or the equivalent helper in the protocol's EModeLogic library). Never compare `userEModeCategory == reserve.configuration.getEModeCategory()` directly in paths that affect bonuses, price source sel"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'executeLiquidationCall|liquidationCall'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'executeLiquidationCall|liquidationCall|_liquidate|calculateUserAccountData'}, {'function.body_contains_regex': 'userEModeCategory|params\\.userEModeCategory|eModeCategory'}, {'function.body_contains_regex': 'liquidationBonus\\s*=\\s*eModeCategories|priceSource|getEModeCategory'}, {'function.body_not_contains_regex': 'EModeLogic\\s*\\.\\s*isInEModeCategory|isInEModeCategory\\s*\\(\\s*(params\\.)?userEModeCategory\\s*,'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-emode-liquidation-category-mismatch-default-price-source: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
