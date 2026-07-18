"""
r74-liquidation-rewards-incorrect-calc — generated from reference/patterns.dsl/r74-liquidation-rewards-incorrect-calc.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-liquidation-rewards-incorrect-calc.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74LiquidationRewardsIncorrectCalc(AbstractDetector):
    ARGUMENT = "r74-liquidation-rewards-incorrect-calc"
    HELP = "Liquidation reward computed without converting debt and collateral to a common unit; reward size drifts from intent when price is != 1:1."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-liquidation-rewards-incorrect-calc.yaml"
    WIKI_TITLE = "Liquidation reward computed on mixed units (debt vs collateral)"
    WIKI_DESCRIPTION = "Lending protocols grant liquidators a bonus equal to a percentage of the collateral value seized. A common implementation bug is to apply the bonus percentage to the debt-denominated amount repaid rather than the collateral-denominated amount seized. When collateral price != debt price (which is the entire point of liquidation — collateral has dropped in value), the computed bonus diverges from th"
    WIKI_EXPLOIT_SCENARIO = "A lending protocol's liquidate() computes `liquidatorReward = debtRepaid * 105 / 100` intending '5% bonus on repaid debt.' But the bonus is meant to be '5% of the collateral seized.' When the user's collateral has dropped such that collateral_value / debt_value = 0.9 at liquidation, a liquidator paying 1000 debt should seize 1000*1.05 = 1050 worth of collateral, but the contract computes the bonus"
    WIKI_RECOMMENDATION = "Compute liquidation reward in the collateral unit system explicitly: `collateralSeized = (debtRepaid * debtPrice / collateralPrice) * (10000 + liquidationBonusBps) / 10000;`. Unit-test the path with skewed price oracles to ensure the bonus is invariant to the debt/collateral price ratio in the direc"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidate|liquidation|Liquidat)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(liquidate|liquidateCall|_liquidate|executeLiquidationCall|liquidationCall|finalizeLiquidation)$'}, {'function.body_contains_regex': '(liquidatorReward|liquidationBonus|liquidationIncentive|reward\\s*=|bonus\\s*=|incentive\\s*=)'}, {'function.body_not_contains_regex': 'getAssetPrice|getCollateralPrice|collateralPrice\\s*\\*|debtPrice\\s*\\*|convertToCollateral|convertToDebt|_convert|priceFeed\\.latestAnswer|toBase|fromBase'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-liquidation-rewards-incorrect-calc: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
