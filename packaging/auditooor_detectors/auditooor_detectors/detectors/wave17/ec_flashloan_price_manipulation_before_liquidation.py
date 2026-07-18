"""
ec-flashloan-price-manipulation-before-liquidation — generated from reference/patterns.dsl/ec-flashloan-price-manipulation-before-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-flashloan-price-manipulation-before-liquidation.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcFlashloanPriceManipulationBeforeLiquidation(AbstractDetector):
    ARGUMENT = "ec-flashloan-price-manipulation-before-liquidation"
    HELP = "Flashloan callback performs an AMM swap (moving price) and then calls liquidate() in the same transaction against the manipulated price."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-flashloan-price-manipulation-before-liquidation.yaml"
    WIKI_TITLE = "Flashloan swap + liquidation in same callback — manipulated price feeds liquidation"
    WIKI_DESCRIPTION = "The flashloan callback executes an AMM swap to move a price oracle, then immediately calls the protocol's liquidation function within the same atomic transaction. The liquidation evaluates collateral against the freshly-manipulated price, letting the attacker receive disproportionate collateral for a small debt repayment."
    WIKI_EXPLOIT_SCENARIO = "Attacker flashloans 10M USDC. In callback: (1) dumps 10M USDC → tokenX on Uniswap, crashing tokenX price 40%. (2) Calls protocol.liquidate(victim) where victim holds tokenX collateral. Protocol reads manipulated tokenX price, sells victim's collateral cheaply to liquidator (attacker). Attacker unwinds dump, repays flashloan, keeps discount."
    WIKI_RECOMMENDATION = "Implement a price-manipulation circuit breaker: detect large price moves (>X%) between the last oracle update and the current read; revert liquidation if within the same block as a large trade in the collateral's pool. Alternatively, use TWAP-only prices for liquidation that cannot be moved in a sin"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'flashLoan|flashloan|IFlashLoanReceiver|onFlashLoan'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'uniswapV2Call|pancakeCall|executeOperation|onFlashLoan|flashCallback'}, {'function.body_contains_regex': 'swap\\s*\\(|swapExactTokens|exactInput|exchange\\s*\\('}, {'function.body_contains_regex': 'liquidat|seize|repayBorrowBehalf'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-flashloan-price-manipulation-before-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
