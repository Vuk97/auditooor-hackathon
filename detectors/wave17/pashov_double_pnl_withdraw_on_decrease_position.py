"""
pashov-double-pnl-withdraw-on-decrease-position — generated from reference/patterns.dsl/pashov-double-pnl-withdraw-on-decrease-position.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-double-pnl-withdraw-on-decrease-position.yaml
Source: auditooor-R75-pashov-GainsNetwork-DecreasePositionSizeUtils-C01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovDoublePnlWithdrawOnDecreasePosition(AbstractDetector):
    ARGUMENT = "pashov-double-pnl-withdraw-on-decrease-position"
    HELP = "Partial-close / leverage-update computes PnL from the full original collateral without subtracting previously realized PnL from earlier partial closes — the trader withdraws the same PnL slice twice."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-double-pnl-withdraw-on-decrease-position.yaml"
    WIKI_TITLE = "Partial-decrease PnL uses existing collateral without subtracting realized-PnL from prior decreases"
    WIKI_DESCRIPTION = "Perp protocols that allow partial closes / leverage decreases compute the trader's refund as `collateralDelta + (existingPnl * delta / existingSize)`, where `existingPnl = f(openPrice, markPrice, leverage) * collateralAmount`. The correct accounting must subtract the fraction of PnL already sent out on previous partial decreases; otherwise the same price appreciation is paid out every time the use"
    WIKI_EXPLOIT_SCENARIO = "Gains Network Decrease-position flow: Trader opens 100x long on ETH with 1000 USDC, price moves +10% → PnL = +1000 USDC. They call decrease(500 USDC collateral). The callback computes `partialTradePnl = (existingPnl * 500/1000) = 500 USDC`, sends 500 + 500 = 1000 USDC. They then call decrease(remaining 500 USDC) — the callback re-derives `existingPnl` from the STILL-OPEN collateralAmount (now 500)"
    WIKI_RECOMMENDATION = "Introduce `trade.realizedPnlCollateral` in storage, increment it by `partialTradePnlCollateral` at every successful decrease, and subtract it when computing `values.existingPnlCollateral` in `prepareCallbackValues`. Add an invariant test: sum of collateralSentToTrader across all partial decreases mu"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'DecreasePositionSize|updateLeverage|closePartial|UpdatePositionSize|PositionManager|perp'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'executeDecrease|prepareCallbackValues|decreasePositionSize|closePartial|updateLeverageCallback'}, {'function.body_contains_regex': 'existingPnl|getPnlPercent|partialTradePnl|existingPositionSizeCollateral'}, {'function.body_contains_regex': 'existingTrade\\.collateralAmount|existingTrade\\.leverage|_existingTrade\\.collateralAmount'}, {'function.body_not_contains_regex': 'realizedPnl|realizedPnlCollateral|alreadyRealized|subRealizedPnl|trade\\.realizedPnl'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pashov-double-pnl-withdraw-on-decrease-position: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
