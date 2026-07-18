"""
perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut — generated from reference/patterns.dsl/perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut.yaml
Source: auditooor-R76-rekt-mango-markets-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpUnrealizedPnlCountsAsBorrowCollateralNoHaircut(AbstractDetector):
    ARGUMENT = "perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut"
    HELP = "Margin engine adds unrealized perp PnL into the user's borrowable collateral value at 100% with no haircut. Low-liquidity-market price manipulation mints withdrawable collateral out of thin air."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut.yaml"
    WIKI_TITLE = "Unrealized perp PnL counted as full-value collateral without a haircut for illiquid markets"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. This row preserves the Mango-style margin-engine shape where `getMaxBorrow`/collateral accounting reads unrealized perp PnL or mark price directly and credits the full positive amount into borrowable collateral with no haircut or concentration penalty. The owned fixture pair distinguishes that shape from a clean variant that applies an expli"
    WIKI_EXPLOIT_SCENARIO = "Attacker deposits $5M USDC to wallet A; opens a massive MNGO-PERP long. From wallet B (and third-party accounts), attacker buys MNGO on every thin-liquidity venue, pumping MNGO from $0.03 to $0.91. Wallet A's unrealized PnL = (long size) x ($0.91 - $0.03) ~= $400M. Mango's risk engine reports wallet A's equity as $405M. Attacker borrows $115M USDC/USDT/BTC/SOL against this equity, withdraws, and w"
    WIKI_RECOMMENDATION = "Apply a haircut to unrealized PnL based on the underlying market's liquidity: `effectivePnl = unrealizedPnl * haircutFactor(market)` where `haircutFactor` starts at e.g. 50% for thin markets and is reduced further based on depth. Cap borrowing against unrealized PnL at a fraction of overall equity, "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(unrealizedPnl|markPrice|getMaxBorrow|getCollateralValue|borrowable|maintenanceMargin)'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)borrow|withdraw|getAccountHealth|getCollateralValue|computeMaintenanceMargin|computeInitMargin|getMaxBorrow'}, {'function.body_contains_regex': '(?i)unrealized(Pnl|PnL|Profit)|markPrice|unrealizedGain|position\\.pnl|_pnl\\s*\\+|_profit\\s*\\+|\\+ perpPosition'}, {'function.body_not_contains_regex': '(?i)pnlHaircut|unrealizedHaircut|HAIRCUT_BPS|concentrationCap|illiquidMarketPenalty|perpUnrealizedMultiplier\\s*<\\s*100|discountFactor\\s*<\\s*1e18'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-unrealized-pnl-counts-as-borrow-collateral-no-haircut: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
