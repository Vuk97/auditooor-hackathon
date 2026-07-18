"""
spearbit-morpho-bad-debt-socialization-skipped-on-empty-market — generated from reference/patterns.dsl/spearbit-morpho-bad-debt-socialization-skipped-on-empty-market.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py spearbit-morpho-bad-debt-socialization-skipped-on-empty-market.yaml
Source: auditooor-R75-spearbit-morpho-blue-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SpearbitMorphoBadDebtSocializationSkippedOnEmptyMarket(AbstractDetector):
    ARGUMENT = "spearbit-morpho-bad-debt-socialization-skipped-on-empty-market"
    HELP = "Bad-debt realization path short-circuits when totalSupplyAssets == 0, so bad debt accumulated on a defaulted position never decrements totalBorrow. The next supplier deposits into a market that already owes more than it holds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/spearbit-morpho-bad-debt-socialization-skipped-on-empty-market.yaml"
    WIKI_TITLE = "Morpho-style lender skips bad-debt socialization when supply side is empty"
    WIKI_DESCRIPTION = "Liquidations that leave a position with `borrow > 0` and `collateral == 0` are supposed to socialise the remaining debt by subtracting from `totalSupplyAssets` (loss to existing suppliers) AND clearing the borrower's obligation from `totalBorrowAssets`. If the write-down is gated on `totalSupplyAssets > 0`, the case where all suppliers have withdrawn before liquidation causes the function to retur"
    WIKI_EXPLOIT_SCENARIO = "Attacker opens a maximally leveraged position, waits for a price shock that puts the position underwater AND rug-pulls their own supply position (they were the sole supplier). The borrow defaults. Liquidator calls liquidate(); bad-debt clear code sees totalSupplyAssets == 0 and returns early. Totals now show `totalBorrowAssets = X, totalSupplyAssets = 0`. Attacker front-runs announcements, supplie"
    WIKI_RECOMMENDATION = "Clear `totalBorrowAssets` / `totalBorrowShares` for the defaulted position *regardless* of supply side. If suppliers are absent, record the bad debt in a `pendingBadDebt` slot that is subtracted from the first future supply. Add an invariant test: for any sequence of actions, `totalBorrowAssets <= t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'liquidate|_liquidate|realizeBadDebt'}]
    _MATCH = [{'function.kind': 'internal_or_public'}, {'function.name_matches': '^(_?liquidate|realizeBadDebt|_settleBadDebt)$'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupplyAssets\\s*>\\s*0|totalSupply(Assets|Shares)\\s*!=\\s*0'}, {'function.body_contains_regex': 'totalBorrow(Assets|Shares)\\s*-='}, {'function.body_not_contains_regex': 'else\\s*\\{[^}]*totalBorrow|pendingBadDebt|deferredBadDebt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — spearbit-morpho-bad-debt-socialization-skipped-on-empty-market: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
