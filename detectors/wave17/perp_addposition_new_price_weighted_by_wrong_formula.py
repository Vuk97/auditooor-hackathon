"""
perp-addposition-new-price-weighted-by-wrong-formula — generated from reference/patterns.dsl/perp-addposition-new-price-weighted-by-wrong-formula.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-addposition-new-price-weighted-by-wrong-formula.yaml
Source: auditooor-R75-c4-2022-12-tigris-H236
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpAddpositionNewPriceWeightedByWrongFormula(AbstractDetector):
    ARGUMENT = "perp-addposition-new-price-weighted-by-wrong-formula"
    HELP = "New entry price on addToPosition is computed as a linear margin-weighted average of the two prices. The correct weighted average is `P1*P2*(M1+M2)/(M1*P2 + M2*P1)` (asset-amount-weighted). User loses or gains ~price-variance on every add; over many adds the bias compounds."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-addposition-new-price-weighted-by-wrong-formula.yaml"
    WIKI_TITLE = "addToPosition uses margin-weighted mean of prices instead of asset-amount-weighted"
    WIKI_DESCRIPTION = "A perp position is characterised by margin M, leverage L, and entry price P. Notional asset amount = (M*L)/P. When you add margin M2 at price P2, the new entry price must equal `(notional1 + notional2)/(amount1 + amount2)`: `Pnew = (M1*L + M2*L) / (M1*L/P1 + M2*L/P2) = P1*P2*(M1+M2) / (M1*P2 + M2*P1)`. A linear weighted mean `P1*M1/(M1+M2) + P2*M2/(M1+M2)` is algebraically different and biased — i"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice long 1 ETH at P1=3000, margin=100, leverage=30. (2) ETH rises to 3500; Alice wants to add. (3) `addToPosition(M2=100)` at P2=3500. Naive `Pnew = 3000*100/200 + 3500*100/200 = 3250`. Correct `Pnew = 3000*3500*200 / (100*3500 + 100*3000) = 2_100_000_000 / 650_000 ≈ 3231`. (4) Alice's entry is 3250, correct is 3231. When she closes later at 3500, her PnL is `(3500-3250)*amount = 250 × amoun"
    WIKI_RECOMMENDATION = "Implement the correct formula: `_newPrice = _trade.price * _price * _newMargin / (_trade.margin * _price + _addMargin * _trade.price)`. Add a unit test that pins the result for hand-computable inputs: 1 ETH at 3000 + 1 ETH at 3500 should yield 3230.77 (not 3250). Consider tracking notional-asset dir"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(addToPosition|_addToPosition|increasePosition|averageEntryPrice)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(addToPosition|_addToPosition|increasePosition|averagePrice|_calculateNewPrice)'}, {'function.body_contains_regex': '_newPrice|newEntryPrice|avgPrice|averagePrice'}, {'function.body_contains_regex': '(trade\\.price|entryPrice|p1)\\s*\\*\\s*(trade\\.margin|m1)\\s*/\\s*_newMargin\\s*\\+\\s*(_price|p2)\\s*\\*\\s*(_addMargin|m2)\\s*/\\s*_newMargin'}, {'function.body_not_contains_regex': '\\*\\s*_newMargin\\s*/\\s*\\(\\s*(trade\\.margin|m1)\\s*\\*\\s*(_price|p2)\\s*\\+\\s*(_addMargin|m2)\\s*\\*\\s*(trade\\.price|p1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-addposition-new-price-weighted-by-wrong-formula: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
