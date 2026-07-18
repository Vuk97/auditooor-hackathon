"""
aave-emode-category-config-allows-ltv-or-lt-zero — generated from reference/patterns.dsl/aave-emode-category-config-allows-ltv-or-lt-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-emode-category-config-allows-ltv-or-lt-zero.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-383bde5f8f
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveEmodeCategoryConfigAllowsLtvOrLtZero(AbstractDetector):
    ARGUMENT = "aave-emode-category-config-allows-ltv-or-lt-zero"
    HELP = "eMode category configurator accepts ltv=0 and/or liquidationThreshold=0. Because assets inside an eMode inherit the category thresholds, this silently disables all inner assets as collateral or allows HF to hit a divide path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-emode-category-config-allows-ltv-or-lt-zero.yaml"
    WIKI_TITLE = "setEModeCategory accepts zero LTV or liquidation threshold, silently un-collateralising member assets"
    WIKI_DESCRIPTION = "Aave v3 PoolConfigurator.setEModeCategory sets the LTV, liquidation threshold and liquidation bonus for an entire eMode category. Every asset whose reserveConfiguration.getEModeCategory() matches uses these parameters while the user is opted into the category. Pre-fix the configurator only checked the existing invariants (lt>=ltv, liquidationBonus>=1e4). It did NOT reject ltv==0 or liquidationThre"
    WIKI_EXPLOIT_SCENARIO = "Risk admin updates stablecoins eMode to tighten liquidationBonus but fat-fingers the ltv field to 0. All users with at least one stablecoin supplied and opted into the stablecoins category instantly see that supply contribute 0 collateral weight. Existing borrows against the stablecoin eMode category become liquidatable immediately, before any user can react to the governance transaction. An MEV b"
    WIKI_RECOMMENDATION = "In setEModeCategory require: `ltv != 0`, `liquidationThreshold != 0`, and for every reserve already tagged into the category `ltv > reserve.ltv` and `liquidationThreshold > reserve.liquidationThreshold` (PR #592). If the intent is to deprecate an eMode category, first migrate all assets out via `set"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'configureEModeCategory|setEModeCategory'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'configureEModeCategory|setEModeCategory|_setEModeCategory'}, {'function.body_contains_regex': 'liquidationBonus|liquidationThreshold|ltv'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*ltv\\s*!=\\s*0|require\\s*\\(\\s*liquidationThreshold\\s*!=\\s*0|require\\s*\\(\\s*liquidationThreshold\\s*>\\s*0|require\\s*\\(\\s*ltv\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-emode-category-config-allows-ltv-or-lt-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
