"""
pashov-curve-virtualprice-no-twap-lp-oracle — generated from reference/patterns.dsl/pashov-curve-virtualprice-no-twap-lp-oracle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-curve-virtualprice-no-twap-lp-oracle.yaml
Source: auditooor-R75-pashov-StakeDAO-CurveOracle-M08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovCurveVirtualpriceNoTwapLpOracle(AbstractDetector):
    ARGUMENT = "pashov-curve-virtualprice-no-twap-lp-oracle"
    HELP = "Curve LP oracle reads `get_virtual_price()` or `price_oracle()` spot — spot values are flash-loan manipulable when the pool is imbalanced, so Morpho/lending integrations can be exploited to force liquidations."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-curve-virtualprice-no-twap-lp-oracle.yaml"
    WIKI_TITLE = "Curve LP/stableswap oracle uses spot get_virtual_price — flash-loan manipulable"
    WIKI_DESCRIPTION = "Curve's `get_virtual_price()` and newer Crypto-pool `price_oracle()` return the CURRENT pool state. In a balanced pool these are reliable, but an attacker can sandwich the oracle read with a large imbalancing swap: (1) swap into the pool, skewing reserves, (2) trigger the dependent protocol's liquidation check which reads the manipulated price, (3) revert-swap back. Curve's newer `price_oracle()` "
    WIKI_EXPLOIT_SCENARIO = "StakeDAO CurveLP oracle: `priceLpInPeg = CURVE_POOL.get_virtual_price();` with no smoothing. Attacker borrows a large token via flash loan, swaps into the 3pool (imbalancing it by 20%), which briefly lowers effective LP price by ~5%. Attacker then calls Morpho's liquidation on a target borrower whose health-factor relies on this oracle: HF drops below 1, liquidation bonus paid to attacker. Attacke"
    WIKI_RECOMMENDATION = "Replace spot `get_virtual_price()` with a time-weighted moving average. Options: (a) Curve's own `price_oracle()` (EMA-smoothed, built into crypto pools), (b) a Chainlink-smoothed LP feed if available, (c) self-maintained TWAP by storing `(virtual_price, timestamp)` observations and computing the 30"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'CurveOracle|CurveCryptoswap|CurveStableswap|CurvePool|LPoracle|PriceOracle'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': 'price|getPrice|latestAnswer|_getPrice|getPriceFeed|lpPrice|_computePrice'}, {'function.body_contains_regex': 'get_virtual_price\\s*\\(\\s*\\)|lp_price\\s*\\(\\s*\\)|\\.price_oracle\\s*\\('}, {'function.body_not_contains_regex': 'TWAP|twap|ma_price|price_oracle\\(1\\)|time_weighted|ema\\b|observations|cumulative'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — pashov-curve-virtualprice-no-twap-lp-oracle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
