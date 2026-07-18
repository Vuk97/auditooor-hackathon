"""
cross-market-price-sum-gte-one-leaves-free-taker — generated from reference/patterns.dsl/cross-market-price-sum-gte-one-leaves-free-taker.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cross-market-price-sum-gte-one-leaves-free-taker.yaml
Source: auditooor-R76-cyfrin-myriad-clob-H2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CrossMarketPriceSumGteOneLeavesFreeTaker(AbstractDetector):
    ARGUMENT = "cross-market-price-sum-gte-one-leaves-free-taker"
    HELP = "Cross-market match requires `priceSum >= ONE` (not `== ONE`). When maker notionals overpay, taker notional clamps to 0, taker gets fillAmount tokens free, and surplus collateral is trapped in the exchange."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cross-market-price-sum-gte-one-leaves-free-taker.yaml"
    WIKI_TITLE = "Cross-market order matching: `priceSum >= ONE` (not ==) lets taker collect free tokens while surplus is stuck"
    WIKI_DESCRIPTION = "A CLOB that settles cross-market fills (e.g. NegRisk multi-outcome) validates `require(priceSum >= ONE)` where ONE=1e18. The taker's notional is computed as the REMAINDER: `notional = notionalSoFar >= fillAmount ? 0 : fillAmount - notionalSoFar`. When makers' rounded-down notionals sum above fillAmount (e.g. 0.6+0.6+0.1 = 1.3), the taker notional clamps to 0 — taker pays zero and receives fillAmou"
    WIKI_EXPLOIT_SCENARIO = "Three makers sell at prices 0.60, 0.60, 0.10 for fillAmount=100. Maker notionals: 60 + 60 + 10 = 130. Sum check `>=ONE` passes (1.3e18 >= 1e18). Taker (Charlie) notional = `130 >= 100 ? 0 : 100-130 = 0`. Exchange collects 120 from alice+bob, sends 100 to adapter for Charlie's YES tokens, FeeModule receives 0. Stuck: 20 wcol. Charlie got 100 YES tokens for free."
    WIKI_RECOMMENDATION = "(1) Strict equality: `require(priceSum == ONE)` to force operators to pre-round maker prices exactly. (2) Alternatively, accept priceSum>=ONE but force each buyer to pay their agreed price and route the surplus to the treasury / fee module. Add an invariant: `sum(maker_payments) == fillAmount + tota"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)CTFExchange|PredictionMarket|NegRisk|CrossMarket'}, {'contract.has_function_matching': '(?i)matchCrossMarket|crossMarketMatch|batchMatch'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)matchCrossMarketOrders|crossMarketMatch|matchOrdersBatch|batchSettle'}, {'function.body_contains_regex': '(?i)priceSum\\s*>=\\s*ONE|priceSum\\s*>=\\s*1e18|sumOfPrices\\s*>=\\s*ONE'}, {'function.body_contains_regex': '(?i)notionalSoFar\\s*>=\\s*fillAmount\\s*\\?\\s*0\\s*:\\s*fillAmount\\s*-\\s*notionalSoFar|max\\s*\\(\\s*0\\s*,\\s*fillAmount\\s*-'}, {'function.body_not_contains_regex': '(?i)priceSum\\s*==\\s*ONE|equal.*ONE|strict.*equal'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cross-market-price-sum-gte-one-leaves-free-taker: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
