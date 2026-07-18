"""
Margin liquidation collateral remainder cap off-by-one ratio.

Row-local posture: keep this detector intentionally narrow and honest. The
current proof is only the owned fixture pair showing the exact liquidation-cap
shape `debtInCollateralToken * crLiquidation / PERCENT` without subtracting
`PERCENT`. That is fixture-smoke/source-shape evidence, not a submission-ready
semantic proof.

This row must remain NOT_SUBMIT_READY until broader validation exists.
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MarginLiquidationCollateralRemainderCapOffByOneRatio(AbstractDetector):
    ARGUMENT = "margin-liquidation-collateral-remainder-cap-off-by-one-ratio"
    HELP = (
        "Fixture-smoke heuristic for liquidation-cap math that uses "
        "`debtInCollateralToken * crLiquidation / PERCENT` instead of "
        "`crLiquidation - PERCENT`."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/margin-liquidation-collateral-remainder-cap-off-by-one-ratio.yaml"
    WIKI_TITLE = "Liquidation collateral-remainder cap uses crLiquidation instead of (crLiquidation - 1)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned liquidation path where `collateralRemainderCap` is computed from `debtInCollateralToken * crLiquidation / PERCENT` without subtracting `PERCENT`. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "(1) Loan: debt = 1_000 USDC, collateral at liquidation = 5_000 USDC-worth of ETH (500% over-collat), debtInCollateralToken = 1_000. Liquidation happens when loan is overdue but still way over-collateralised. (2) Correct cap: `1_000 * 0.3 = 300` (maximum 300 USDC above debt to protocol). (3) Written cap: `1_000 * 1.3 = 1_300`. `collateralRemainder = 5_000 - 1_000 = 4_000`. `collateralRemainder = mi"
    WIKI_RECOMMENDATION = "Fix the cap: `collateralRemainderCap = Math.mulDivDown(debtInCollateralToken, state.riskConfig.crLiquidation - PERCENT, PERCENT);`. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(collateralRemainderCap|crLiquidation|protocolProfitCollateralToken|executeLiquidate)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(executeLiquidate|_liquidate|computeLiquidationFee|settleOvercollat)'}, {'function.body_contains_regex': 'collateralRemainderCap\\s*=\\s*Math\\.mulDiv\\w*\\s*\\(\\s*debtInCollateralToken\\s*,\\s*state\\.\\w*\\.crLiquidation'}, {'function.body_not_contains_regex': 'crLiquidation\\s*-\\s*PERCENT|crLiquidation\\s*-\\s*(1e18|100|10000)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — margin-liquidation-collateral-remainder-cap-off-by-one-ratio: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
