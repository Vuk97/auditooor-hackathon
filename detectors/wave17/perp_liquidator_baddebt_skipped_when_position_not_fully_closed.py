"""
perp-liquidator-baddebt-skipped-when-position-not-fully-closed — generated from reference/patterns.dsl/perp-liquidator-baddebt-skipped-when-position-not-fully-closed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-liquidator-baddebt-skipped-when-position-not-fully-closed.yaml
Source: auditooor-R75-c4-2024-05-predy-H189-H28
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpLiquidatorBaddebtSkippedWhenPositionNotFullyClosed(AbstractDetector):
    ARGUMENT = "perp-liquidator-baddebt-skipped-when-position-not-fully-closed"
    HELP = "Liquidation flow gates the bad-debt pull (`safeTransferFrom(liquidator)`) behind a full-closure predicate. Partial liquidation harvests slippage PnL while leaving residual negative margin on the vault — last liquidator is disincentivized, protocol eats the debt."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-liquidator-baddebt-skipped-when-position-not-fully-closed.yaml"
    WIKI_TITLE = "Liquidator bad-debt repayment skipped when only full-closure path checks remainingMargin"
    WIKI_DESCRIPTION = "Perp liquidation functions typically check at the end: `if (!hasPosition) { if (remainingMargin < 0) transferFrom(liquidator, ..., -remainingMargin); }`. The branch only executes when the vault is fully empty. Any liquidator calling with `closeRatio = 0.9999e18` harvests the slippage profit (liquidator buys/sells at bounded-price from the AMM), shrinks position size by 99.99%, and exits without tr"
    WIKI_EXPLOIT_SCENARIO = "(1) Vault has 1 ETH long at entry 3000, mark now 2500, margin 500 USDC. Slippage tolerance 5%. Full liquidation of 1 ETH returns 2500*0.95 = 2375, leaves remainingMargin = 500 + 2375 - 3000 = -125 USDC (bad debt). (2) Honest liquidator would be forced to pay 125 USDC to the pool, net P&L = slippage - 125. (3) Attacker instead calls `liquidate(vaultId, 0.99999e18)`. 99.999% of the position is close"
    WIKI_RECOMMENDATION = "The bad-debt repayment branch must run whenever the position is liquidatable AND the vault equity after the close is negative, regardless of `closeRatio`. Either (a) require full closure when `remainingMargin < 0` would result, i.e. reject partial calls that leave bad debt, or (b) require the liquid"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidate|Liquidate|settleLiquidation|closePositionForLiquidation)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(liquidate|_liquidate|executeLiquidation|liquidatePosition|liquidateCall)'}, {'function.body_contains_regex': '(closeRatio|partialLiquidation|liquidationRatio|closePortion|closePercent)'}, {'function.body_contains_regex': '(remainingMargin|remainingCollateral|negativeMargin|badDebt)'}, {'function.body_contains_regex': '(!hasPosition|fullyLiquidated|isFullyClosed|position\\.size\\s*==\\s*0|openPosition\\s*==\\s*0)'}, {'function.body_not_contains_regex': 'remainingMargin\\s*<\\s*0[\\s\\S]{0,400}transferFrom\\s*\\(\\s*(msg\\.sender|liquidator)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-liquidator-baddebt-skipped-when-position-not-fully-closed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
