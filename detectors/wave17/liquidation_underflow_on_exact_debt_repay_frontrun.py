"""
liquidation-underflow-on-exact-debt-repay-frontrun — generated from reference/patterns.dsl/liquidation-underflow-on-exact-debt-repay-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-underflow-on-exact-debt-repay-frontrun.yaml
Source: auditooor-R73-code4rena-2024-07-loopfi-162
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationUnderflowOnExactDebtRepayFrontrun(AbstractDetector):
    ARGUMENT = "liquidation-underflow-on-exact-debt-repay-frontrun"
    HELP = "Liquidation subtracts user-supplied repay from stale debt; 1-wei front-run triggers underflow-revert."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-underflow-on-exact-debt-repay-frontrun.yaml"
    WIKI_TITLE = "Liquidation debt subtraction unclamped: 1-wei self-repay causes underflow revert"
    WIKI_DESCRIPTION = "Liquidation logic snapshots the borrower's debt once, then computes `newDebt = debt - amountToRepay` where `amountToRepay` is controlled by the liquidator and was fetched via a prior view call. If the borrower pre-pays any dust (even 1 wei) between the view and the liquidation, the subtraction reverts with an arithmetic underflow."
    WIKI_EXPLOIT_SCENARIO = "Borrower monitors mempool. Liquidator queries `virtualDebt(owner)` returning 80e18, then submits `liquidatePosition(owner, 80e18)`. Borrower front-runs with `repay(owner, 1)`, shrinking debt to 80e18-1. The liquidator's tx executes `newDebt = (80e18-1) - 80e18` and reverts. The borrower repeats this as their position stays underwater."
    WIKI_RECOMMENDATION = "Clamp the repayment to the current debt inside the liquidation: `uint256 effective = Math.min(amountToRepay, currentDebt); newDebt = currentDebt - effective;` and refund the unused amount. Always treat external view-supplied amounts as upper bounds, not exact values."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)liquidat|repayOnBehalf|forceRepay'}, {'function.body_contains_regex': '(?s)(newDebt|remainingDebt)\\s*=\\s*\\w*debt\\w*\\s*-\\s*(amountToRepay|repayAmount|amount)'}, {'function.body_not_contains_regex': '(?i)(min\\s*\\(|clamp|if\\s*\\(\\s*\\w*debt\\w*\\s*<\\s*\\w*amount)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-underflow-on-exact-debt-repay-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
