"""
ec-liquidation-price-read-in-flashloan-callback — generated from reference/patterns.dsl/ec-liquidation-price-read-in-flashloan-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-liquidation-price-read-in-flashloan-callback.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcLiquidationPriceReadInFlashloanCallback(AbstractDetector):
    ARGUMENT = "ec-liquidation-price-read-in-flashloan-callback"
    HELP = "Liquidation logic reads price inside a flashloan callback; attacker moves price before callback executes and captures inflated liquidation bonus."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-liquidation-price-read-in-flashloan-callback.yaml"
    WIKI_TITLE = "Price read inside flashloan callback used to compute liquidation reward"
    WIKI_DESCRIPTION = "The contract exposes a flashloan callback (executeOperation, uniswapV2Call, etc.) that itself calls a liquidation function and reads a price to compute the liquidation reward. By the time the callback executes the attacker has already manipulated the price source using the flashloaned capital."
    WIKI_EXPLOIT_SCENARIO = "Attacker borrows 10M USDC via flashloan, buys tokenX to move price 30% up, invokes liquidatePosition() inside the callback which reads the manipulated tokenX price to compute collateral-to-seize, seizes 130% of normal collateral, dumps tokenX, repays flashloan."
    WIKI_RECOMMENDATION = "Separate price capture from liquidation execution: record the price at the start of the public liquidation entry point (before any external call) and pass it as a parameter to internal logic. Never allow liquidation reward to depend on a price read inside a callback that can be entered by an arbitra"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'flashLoan|flashloan|uniswapV2Call|pancakeCall|executeOperation|onFlashLoan'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'uniswapV2Call|pancakeCall|executeOperation|onFlashLoan|callbackFn|receiveFlashLoan'}, {'function.body_contains_regex': 'liquidat|liquidatePosition|repayAndLiquidate|forceLiquidate'}, {'function.body_contains_regex': 'getPrice|latestAnswer|latestRoundData|getReserves|slot0|currentPrice'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-liquidation-price-read-in-flashloan-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
