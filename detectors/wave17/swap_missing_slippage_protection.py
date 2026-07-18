"""
swap-missing-slippage-protection — generated from reference/patterns.dsl/swap-missing-slippage-protection.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-missing-slippage-protection.yaml
Source: solodit-cluster-C0262
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapMissingSlippageProtection(AbstractDetector):
    ARGUMENT = "swap-missing-slippage-protection"
    HELP = "Swap/trade/buy/sell function invokes an AMM swap without a visible slippage check (no require on amountOut/received/returned/outputAmount >= …) — user funds exposed to sandwich / MEV extraction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-missing-slippage-protection.yaml"
    WIKI_TITLE = "Missing slippage protection on AMM swap entrypoint"
    WIKI_DESCRIPTION = "A public function that triggers an AMM swap must enforce a minimum-output (or maximum-input) check so that sandwich or MEV bots cannot extract value between quote and execution. This detector flags swap entrypoints whose bodies execute a `.swap` / `swapExact…` / `executeSwap` call but contain no `require(amountOut >= …)`-style guard and no invocation of a named `checkSlippage` / `slippageCheck` he"
    WIKI_EXPLOIT_SCENARIO = "Protocol exposes `swapAndDeposit(tokenIn, amountIn)` which calls `router.swapExactTokensForTokens(amountIn, 0, path, address(this), deadline)`. A sandwich bot front-runs the user, pushes the pool price, and back-runs after the user's swap completes. The user receives far less of `tokenOut` than the spot quote implied; the extracted value goes to the bot."
    WIKI_RECOMMENDATION = "Require a caller-supplied `amountOutMin` and forward it to the router, or compute it from an on-chain TWAP and enforce `require(amountOut >= amountOutMin)` after the swap. Reject `amountOutMin == 0`. Prefer well-audited routers (UniV3 with slippage enforcement, 0x settlement with taker-asset-minimum"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'swap|trade|buy|sell|buyToken|sellToken|swapExactTokens|_swap|_executeSwap'}, {'function.body_contains_regex': {'regex': '\\.swap\\s*\\(|\\.swapExact|swapExactTokensFor|executeSwap|_doSwap'}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:[^;)]*\\b)?(amountOut|received|returned|outputAmount)\\b[^;)]*>=|\\bamountOutMin\\s*>=|check[_s]lippage|slippageCheck'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-missing-slippage-protection: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
