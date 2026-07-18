"""
curve-pool-calc-precision-loss — generated from reference/patterns.dsl/curve-pool-calc-precision-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curve-pool-calc-precision-loss.yaml
Source: solodit-cluster/C0068
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CurvePoolCalcPrecisionLoss(AbstractDetector):
    ARGUMENT = "curve-pool-calc-precision-loss"
    HELP = "Curve pool call (get_dy / exchange / add_liquidity / remove_liquidity_one_coin) invoked without a visible min-received / minOut slippage check — precision loss and sandwich / MEV risk; hardcoded i,j indices additionally break on pools with native ETH."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curve-pool-calc-precision-loss.yaml"
    WIKI_TITLE = "Curve pool integration: precision loss / missing minOut / hardcoded coin indices"
    WIKI_DESCRIPTION = "A state-mutating public function invokes a Curve pool primitive (get_dy, exchange, add_liquidity, remove_liquidity_one_coin) but the function body does not enforce a minimum-output / minimum-received guard (`require(received >= minOut)` or equivalent) and does not forward a caller-supplied _minOut parameter. Integrations of this shape exhibit two closely related failure modes documented across the"
    WIKI_EXPLOIT_SCENARIO = "Protocol's Spell contract calls `curvePool.exchange(0, 1, amountIn, 0)` to swap USDC for USDT, no minOut enforced. On a metapool whose coin layout differs from the integrator's assumption, coin index 0 is 3CRV (LP token) rather than USDC and the call either reverts unexpectedly (blocking user positions) or routes through a mispriced virtual-LP path. Alternatively, on a stableswap with native ETH, "
    WIKI_RECOMMENDATION = "Require the caller to supply `_minOut` (or compute it from an on-chain TWAP / Chainlink reference price with a tolerance band) and forward it to `exchange` / `remove_liquidity_one_coin` as the final argument. Additionally: (1) look up coin indices at runtime via `pool.coins(i)` rather than hardcodin"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'ICurvePool|ICurve|ICurveV2|IStableSwap|get_dy|add_liquidity|remove_liquidity_one_coin'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.body_contains_regex': {'regex': '\\.get_dy\\s*\\(|\\.exchange\\s*\\(|\\.add_liquidity\\s*\\(|\\.remove_liquidity'}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[^;)]*(received|out|amount)\\b[^;)]*>=\\s*[^;)]*(min|_min|_slippage)|_minOut|minReceived|minOutput|_slippage'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — curve-pool-calc-precision-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
