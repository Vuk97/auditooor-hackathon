"""
uniswap-v3-slot0-spot-price — generated from reference/patterns.dsl/uniswap-v3-slot0-spot-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-v3-slot0-spot-price.yaml
Source: solodit-cluster/uniswap-v3-price-manipulation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapV3Slot0SpotPrice(AbstractDetector):
    ARGUMENT = "uniswap-v3-slot0-spot-price"
    HELP = "Function reads Uniswap V3 pool.slot0() / sqrtPriceX96 and uses it directly as a price without a TWAP (observe / OracleLibrary.consult) — flashloan-manipulable spot price."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-v3-slot0-spot-price.yaml"
    WIKI_TITLE = "Uniswap V3 slot0 used as price without TWAP (flashloan-manipulable)"
    WIKI_DESCRIPTION = "slot0() on a Uniswap V3 pool returns the live post-swap sqrtPriceX96 and tick. Reading this as a price feed lets a single-block attacker dislocate the pool via flashloan, trigger the victim call (mint / borrow / collateral check), and restore the pool in the same tx. Canonical mitigation is OracleLibrary.consult or pool.observe for a time-weighted average. This detector flags functions that read s"
    WIKI_EXPLOIT_SCENARIO = "A lending protocol computes collateral value from `(sqrtPriceX96, , , , , , ) = pool.slot0();` and converts to a price via FullMath. An attacker flash-borrows one side of the pool, swaps to move sqrtPriceX96 up by 30%, calls `borrow()` while the price is dislocated, and the victim mints more debt than the underlying position would support at the true TWAP. The attacker swaps back and repays the fl"
    WIKI_RECOMMENDATION = "Replace slot0() reads with `OracleLibrary.consult(pool, period)` or a direct `pool.observe(secondsAgos)` TWAP over a protocol-appropriate window (typically 30 min to several hours). Never derive mint / borrow / liquidation-threshold prices from an instantaneous sqrtPriceX96. If slot0 is genuinely ne"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'IUniswapV3Pool|IUniswapV3PoolState|slot0\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '\\.slot0\\s*\\(\\s*\\)|sqrtPriceX96|slot0'}}, {'function.body_not_contains_regex': '\\.observe\\s*\\(|OracleLibrary\\.consult|getQuoteAtTick|TWAP|timeWeightedAverage|_consult'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-v3-slot0-spot-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
