"""
swap-pool-adapter-not-matched-to-underlying — generated from reference/patterns.dsl/swap-pool-adapter-not-matched-to-underlying.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-pool-adapter-not-matched-to-underlying.yaml
Source: solodit/sherlock/illuminate-H16-3728
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapPoolAdapterNotMatchedToUnderlying(AbstractDetector):
    ARGUMENT = "swap-pool-adapter-not-matched-to-underlying"
    HELP = "Swap entry point takes `(underlying, pool)` as two independent caller inputs and never checks that the pool trades the underlying. With user-supplied `minOut=0`, attacker drains any other token the contract holds by routing through a mismatched pool + MEV sandwich."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-pool-adapter-not-matched-to-underlying.yaml"
    WIKI_TITLE = "Swap pool/adapter not validated against supplied underlying — protocol balances drained"
    WIKI_DESCRIPTION = "A lending / structured-product contract routes user deposits through an external AMM/router with two independent caller parameters: `underlying` (token the user deposits) and `pool` (AMM to swap in). The function pulls `underlying` from the user, then tells the router to `swapExactTokensForTokens(lent, minOut, path, ...)`, trusting the user-supplied `pool`. If `pool` trades a different asset (stET"
    WIKI_EXPLOIT_SCENARIO = "`Lender` has accumulated 100 stETH in fees. Attacker calls `lend(principal=APWine, u=DAI, a=100, r=0, d=..., x=apwineRouter, pool=stEthPool)`. `Lender` pulls 100 DAI, approves router (already approved), calls router.swapExactAmountIn on stEthPool with minAmountOut=0. The router draws from Lender's existing stETH balance (which it had approved for the router as part of setup) and swaps into APWine "
    WIKI_RECOMMENDATION = "Before calling the external swap, assert the pool's tokens match `underlying`: `require(IPool(pool).token0() == u || IPool(pool).token1() == u)` (or the adapter's `asset()`). Consider maintaining a protocol-controlled allowlist of (underlying => pool) pairs, and let the caller only pick among those."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'Safe\\.transferFrom\\s*\\([^)]*\\bIERC20\\s*\\(\\s*\\w+\\s*\\)|safeTransferFrom\\s*\\([^)]*msg\\.sender'}, {'function.body_contains_regex': '\\.swap(Exact)?(Amount|Tokens)?\\s*\\(|_swap\\s*\\(|IRouter\\(.*\\)\\.swap'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*\\.(token0|token1|asset|underlying)\\s*\\(\\s*\\)\\s*==\\s*(u|underlying|token|assetIn)|poolAsset\\s*==\\s*underlying'}, {'function.signature_regex': 'uint256|uint'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-pool-adapter-not-matched-to-underlying: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
