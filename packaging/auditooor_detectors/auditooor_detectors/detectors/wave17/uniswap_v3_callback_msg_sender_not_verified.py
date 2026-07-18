"""
uniswap-v3-callback-msg-sender-not-verified — generated from reference/patterns.dsl/uniswap-v3-callback-msg-sender-not-verified.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-v3-callback-msg-sender-not-verified.yaml
Source: solodit-cluster/uniswap-callback-unverified-sender
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapV3CallbackMsgSenderNotVerified(AbstractDetector):
    ARGUMENT = "uniswap-v3-callback-msg-sender-not-verified"
    HELP = "AMM-pool callback (uniswapV3SwapCallback / uniswapV3MintCallback / uniswapV2Call / pancakeCall / algebraSwapCallback / onMint / onSwap) is external/public but the body never verifies msg.sender == pool. Anyone can invoke the callback with fake amount0Delta / amount1Delta to drain the contract's bala"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-v3-callback-msg-sender-not-verified.yaml"
    WIKI_TITLE = "Uniswap-style AMM callback does not verify msg.sender is the pool"
    WIKI_DESCRIPTION = "Pool-pair callbacks (Uniswap V2 `uniswapV2Call`, Uniswap V3 `uniswapV3SwapCallback` / `uniswapV3MintCallback` / `uniswapV3FlashCallback`, PancakeSwap `pancakeCall`, Algebra `algebraSwapCallback`, and protocol-internal `onSwap` / `onMint` aliases) are invoked by the AMM pool after a swap or mint with authoritative `amount0Delta` / `amount1Delta` parameters. The callback is expected to transfer thos"
    WIKI_EXPLOIT_SCENARIO = "A router contract implements `uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data)` and, upon a positive delta, calls `IERC20(token).transfer(msg.sender, uint256(delta))`. No `require(msg.sender == pool)` is present. Attacker calls `router.uniswapV3SwapCallback(1e18, 0, data)` directly with `data` encoded to name the router's collateral token. The router transfers 1"
    WIKI_RECOMMENDATION = "At the top of every AMM-pool callback, verify the caller is the pool this contract expects to be interacting with. For Uniswap V3 the canonical check is `require(msg.sender == PoolAddress.computeAddress(factory, poolKey));` derived from the data parameter; for V2 / fork callbacks use `require(msg.se"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'uniswapV(2|3)(Swap|Mint|Flash)?Callback|uniswapV2Call|panCakeCall|pancakeCall|swapCallback|algebraSwapCallback|onMint|onSwap'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.sender\\s*==\\s*(pool|_pool|POOL|uniswapPool|address\\s*\\(\\s*pool|IUniswapV3Pool|PoolAddress)|onlyPool|_verifyPool'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-v3-callback-msg-sender-not-verified: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
