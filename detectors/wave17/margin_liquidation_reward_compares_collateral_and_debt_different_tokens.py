"""
Margin liquidation reward compares collateral and debt token units.

Row-local posture: keep this detector intentionally narrow. The current proof is
only the owned fixture pair showing a direct liquidation reward assignment where
`Math.min` compares collateral surplus against debt future value multiplied by a
reward percent, without a visible debt-to-collateral conversion.

This row must remain NOT_SUBMIT_READY until a real impact contract and broader
variant coverage are locked.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MarginLiquidationRewardComparesCollateralAndDebtDifferentTokens(AbstractDetector):
    ARGUMENT = "margin-liquidation-reward-compares-collateral-and-debt-different-tokens"
    HELP = (
        "Fixture-smoke heuristic for `liquidatorReward = Math.min(collateralSurplus, "
        "debtFutureValue * rewardPct / PERCENT)` where the first side is collateral "
        "units and the second side is debt-token face value."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/margin-liquidation-reward-compares-collateral-and-debt-different-tokens.yaml"
    WIKI_TITLE = "Liquidator-reward min() compares values in different token units (collateral vs. debt)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned liquidation reward path where `liquidatorReward = Math.min(collateralSurplus, debtFutureValue * liquidatorRewardPercent / PERCENT)` appears without a visible debt-to-collateral conversion. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "(1) Debt: 5_000 USDC future value; rewardPct = 5%. Y = 5_000 * 5% = 250 (USDC). (2) Collateral surplus after debt: 0.2 ETH. At ETH=2_000 that's 400 USDC. X = 0.2 (ETH units, actually 0.2e18). (3) Code: `Math.min(0.2e18, 250e6)` — if units happen to match as e6 for USDC, ETH is e18, so `Math.min(200_000_000_000_000_000, 250_000_000) = 250_000_000`. Reward = 250e6, but that's 250 USDC, not 250 ETH. "
    WIKI_RECOMMENDATION = "Convert the debt-token reward side into collateral units before the `min`, then compare collateral units against collateral units. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?s)(?=.*\\bcollateralToken\\b)(?=.*\\bdebtToken\\b)(?=.*\\b(?:futureValue|debtFutureValue)\\b)(?=.*\\bliquidatorReward\\b)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(executeLiquidate|_liquidate|computeLiquidatorReward|liquidate)'}, {'function.body_contains_regex': '(?:uint256\\s+)?liquidatorReward\\s*=\\s*Math\\.min\\s*\\(\\s*(?:assignedCollateral\\s*-\\s*debtInCollateralToken|collateralSurplus|remainderCollateral)\\s*,\\s*(?:debtFutureValue|futureValue|debtValue|debtAmount|faceValue)\\s*[\\s\\S]{0,160}?(?:rewardPct|rewardPercent|liquidatorRewardPercent|liquidationRewardPercent)\\s*[\\s\\S]{0,80}?\\)'}, {'function.body_contains_regex': '(?i)collateralToken\\s*\\.\\s*(?:safeTransfer|transfer)\\s*\\([^;]*liquidatorReward'}, {'function.body_not_contains_regex': '(?i)(toCollateralToken|convertToCollateral|debtRewardInCollateral|mulDivPrice|oraclePrice|priceFeed|debt\\s*\\*\\s*price|price\\s*\\*\\s*debt)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — margin-liquidation-reward-compares-collateral-and-debt-different-tokens: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
