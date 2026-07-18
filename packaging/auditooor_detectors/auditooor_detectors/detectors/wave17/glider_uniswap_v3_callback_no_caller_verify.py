"""
glider-uniswap-v3-callback-no-caller-verify — generated from reference/patterns.dsl/glider-uniswap-v3-callback-no-caller-verify.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v3-callback-no-caller-verify.yaml
Source: hexens-glider/uniswap-v3-callback-function-doesnt-verify-caller
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV3CallbackNoCallerVerify(AbstractDetector):
    ARGUMENT = "glider-uniswap-v3-callback-no-caller-verify"
    HELP = "Uniswap V3 callback (`uniswapV3SwapCallback`, `uniswapV3FlashCallback`, `uniswapV3MintCallback`) does not verify `msg.sender` is a canonical Uniswap V3 pool. Anyone can invoke the callback directly and steer its `transferFrom(user, to, amount)` logic to drain approvals."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v3-callback-no-caller-verify.yaml"
    WIKI_TITLE = "Uniswap V3 callback missing caller verification"
    WIKI_DESCRIPTION = "V3 callbacks are expected to be invoked by the pool itself in the same transaction. The callback typically transfers tokens from a user who approved the periphery, using the `data` parameter to encode token/payer. If the callback does not verify that msg.sender is a genuine pool, an attacker calls it directly with crafted data — the callback pulls tokens from the victim's approved balance to the a"
    WIKI_EXPLOIT_SCENARIO = "`SwapRouter.uniswapV3SwapCallback(amount0Delta, amount1Delta, data)` is external without sender check. Attacker ABI-encodes `data = (tokenIn, user, amount, fee)` where `user` has approved the router. Attacker calls `router.uniswapV3SwapCallback(amount, 0, data)` → router pulls `amount` of tokenIn from user to the pool specified by fee (or anywhere the callback sends to) — funds stolen."
    WIKI_RECOMMENDATION = "Compute the canonical pool via `PoolAddress.computeAddress(factory, poolKey)` and `require(msg.sender == pool)`. Reference: Uniswap SwapRouter `verifyCallback`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'uniswapV3(Swap|Flash|Mint)Callback'}]
    _MATCH = [{'function.name_matches': '^(uniswapV3SwapCallback|uniswapV3FlashCallback|uniswapV3MintCallback)$'}, {'function.kind': 'external_or_public'}, {'function.body_not_contains_regex': 'verifyCallback|msg\\.sender\\s*==\\s*address\\s*\\(\\s*pool|msg\\.sender\\s*==\\s*_?pool|msg\\.sender\\s*==\\s*PoolAddress\\.computeAddress|computePoolAddress|require\\s*\\(\\s*msg\\.sender\\s*==\\s*\\w*[Pp]ool'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-uniswap-v3-callback-no-caller-verify: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
