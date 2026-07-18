"""
oracle-atomic-front-run-manipulation — generated from reference/patterns.dsl/oracle-atomic-front-run-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-atomic-front-run-manipulation.yaml
Source: solodit/C0267
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleAtomicFrontRunManipulation(AbstractDetector):
    ARGUMENT = "oracle-atomic-front-run-manipulation"
    HELP = "External/public price-sensitive action (liquidate/redeem/swap/withdraw/borrow/repay) triggers an oracle push or pull update in the same transaction without any time-lag or TWAP defense — caller can atomically front-run the protocol."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-atomic-front-run-manipulation.yaml"
    WIKI_TITLE = "Oracle atomic front-run: price-sensitive action updates oracle in same tx"
    WIKI_DESCRIPTION = "The function performs a price-sensitive state change (liquidation, swap, redemption, borrow, repay, or withdrawal) and invokes a push or pull oracle primitive (updatePriceFeeds, updatePrice, submitPrice, refreshPrice, pokePrice) in the same call. No time-lag gate, TWAP, or moving-average intermediates between the fresh price and the settlement math, so the caller can compose an MEV bundle that upd"
    WIKI_EXPLOIT_SCENARIO = "A lending market exposes liquidate(user) which internally calls pyth.updatePriceFeeds(pricesUpdateData) then reads the fresh price via pyth.getPrice(asset). An attacker buys the victim's debt position on the cheap by: (1) fetching a signed price update from Pyth's Hermes endpoint that reflects a market dip, (2) bundling updatePriceFeeds + liquidate in one tx, (3) pocketing the liquidation bonus ag"
    WIKI_RECOMMENDATION = "Never let an externally-triggered price-sensitive action update the oracle in the same transaction. Enforce a minimum delay (block.timestamp - lastUpdate >= minDelayBetween) between price updates and settlement, consume a TWAP or moving-average over multiple blocks, or separate price-update authorit"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(oracle|priceOracle|pythOracle|pullOracle|priceFeed)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(liquidate|redeem|swap|trade|withdraw|borrow|repay)'}, {'function.body_contains_regex': {'regex': '(updatePriceFeeds\\s*\\(|updatePrice\\s*\\(|updatePriceData\\s*\\(|pyth\\.updatePriceFeeds|oracle\\.updatePrice|submitPrice\\s*\\(|refreshPrice\\s*\\(|pokePrice\\s*\\()'}}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*-\\s*updatedAt|minDelayBetween|twap|getTWAP|SMA_'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-atomic-front-run-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
