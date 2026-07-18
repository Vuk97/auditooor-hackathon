"""
curve-pool-native-eth-handling — generated from reference/patterns.dsl/curve-pool-native-eth-handling.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py curve-pool-native-eth-handling.yaml
Source: solodit-cluster/C0092
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CurvePoolNativeEthHandling(AbstractDetector):
    ARGUMENT = "curve-pool-native-eth-handling"
    HELP = "Contract wraps/unwraps WETH inline with a Curve pool call but has no native-ETH vs WETH branch — if the pool's coin layout contains native ETH (sentinel 0xEeeE…), user deposits are silently routed to the wrong side and funds get stuck or revert."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/curve-pool-native-eth-handling.yaml"
    WIKI_TITLE = "Curve pool integration: native ETH vs WETH handling mismatch"
    WIKI_DESCRIPTION = "A state-mutating public function performs a Curve pool operation (get_dy, exchange, add_liquidity, remove_liquidity) alongside a WETH wrap or unwrap, yet contains no visible branch on whether the pool uses native ETH or WETH for its ETH-denominated coin. Curve pools expose their coin layout via `coins(i)`; pools that use native ETH return the sentinel address 0xEeeE…EeEe, while pools that use WETH"
    WIKI_EXPLOIT_SCENARIO = "Protocol deploys a StrategyETH contract that wraps user-supplied ETH via `WETH.deposit{value: msg.value}()` and then calls `curvePool.add_liquidity([wethAmount, 0], 0)` to mint LP shares. The target Curve pool is a native-ETH pool (ETH at coins(0), stETH at coins(1)). On deposit, `add_liquidity` expects `msg.value` to fund the ETH leg and reverts when given a WETH amount via ERC20 accounting. In a"
    WIKI_RECOMMENDATION = "Before any Curve call, resolve the pool's ETH side explicitly: read `pool.coins(i)` and compare against the native-ETH sentinel `0xEeeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeE` (or the canonical WETH address for the chain). Encode an `IS_NATIVE_POOL` / `_isNativePool` bool or take a constructor-time arg"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'ICurvePool|ICurve|ICurveV2|IStableSwap|curvePool|get_dy|add_liquidity|remove_liquidity_one_coin'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.body_contains_regex': {'regex': 'ICurvePool|curvePool\\.|\\.get_dy\\s*\\(|\\.exchange\\s*\\(|\\.add_liquidity\\s*\\(|\\.remove_liquidity'}}, {'function.body_contains_regex': {'regex': 'IWETH|\\bWETH\\b|weth\\.deposit\\s*\\(|weth\\.withdraw\\s*\\(|\\.wrap\\s*\\(\\s*msg\\.value|\\.unwrap\\s*\\('}}, {'function.body_not_contains_regex': 'useNativeEth|IS_NATIVE_POOL|_isNativePool|isNativePool|SENTINEL_ETH|0xEeeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeeEEeE|pool\\.coins\\s*\\(\\s*0\\s*\\)\\s*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — curve-pool-native-eth-handling: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
