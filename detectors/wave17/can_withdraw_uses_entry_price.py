"""
can-withdraw-uses-entry-price — generated from reference/patterns.dsl/can-withdraw-uses-entry-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-withdraw-uses-entry-price.yaml
Source: cantina/2024-2025-reya-royco-synthetics-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanWithdrawUsesEntryPrice(AbstractDetector):
    ARGUMENT = "can-withdraw-uses-entry-price"
    HELP = "Withdraw / close / settle path reads `position.entryPrice` instead of live oracle — user escapes at favorable entry price after market moves against them."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-withdraw-uses-entry-price.yaml"
    WIKI_TITLE = "Withdraw path uses stored entry price instead of current oracle"
    WIKI_DESCRIPTION = "Perpetual and synthetic vaults record the price at which a position was opened to compute PnL. The same stored price must never be used for collateral-value checks at withdraw time, because it pins user's notional to the past and lets them skip adverse market moves. When `withdraw()` or `settle()` values the position at `position.entryPrice` instead of reading a fresh oracle, the user can keep a l"
    WIKI_EXPLOIT_SCENARIO = "Reya / Royco / synthetic-asset class (Cantina 2024-2025): user opens a 100 ETH long at $3,000 (entryPrice = $3,000). ETH drops to $2,000, position now worth 100 × $2,000 = $200k, but `withdraw()` values collateral as `shares * position.entryPrice = 100 × $3,000 = $300k` and releases that amount. The protocol just paid out $100k the user hadn't earned. Mirror case: user opens a short at $3,000, ETH"
    WIKI_RECOMMENDATION = "Separate PnL accounting (uses entryPrice) from notional valuation (must use live oracle). At every settlement / withdraw / liquidate call site: `uint256 currentPrice = oracle.getPrice(asset); uint256 notional = size * currentPrice / 1e18;`. Never read `position.entryPrice` into the payout formula. A"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Position|entryPrice|openPrice|avgPrice|priceAtEntry'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(withdraw|close|settle|redeem|liquidate|exit|unwind)'}, {'function.body_contains_regex': '(position|user|account)\\w*\\.(entryPrice|openPrice|avgPrice|priceAtEntry|initialPrice)'}, {'function.body_not_contains_regex': '(getPrice|latestAnswer|latestRoundData|oracle\\.|priceFeed\\.|currentPrice|peek\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-withdraw-uses-entry-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
