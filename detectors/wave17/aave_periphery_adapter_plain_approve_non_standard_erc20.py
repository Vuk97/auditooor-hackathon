"""
aave-periphery-adapter-plain-approve-non-standard-erc20 — generated from reference/patterns.dsl/aave-periphery-adapter-plain-approve-non-standard-erc20.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-periphery-adapter-plain-approve-non-standard-erc20.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-periphery-f5d0af92d5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AavePeripheryAdapterPlainApproveNonStandardErc20(AbstractDetector):
    ARGUMENT = "aave-periphery-adapter-plain-approve-non-standard-erc20"
    HELP = "Aave periphery adapter (ParaSwap/aggregator) uses plain IERC20.approve() with the reset-to-0 dance. Non-standard ERC20s (USDT, weird returnless tokens) silently revert or return false, which plain approve does not check — safeApprove must be used."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-periphery-adapter-plain-approve-non-standard-erc20.yaml"
    WIKI_TITLE = "Periphery adapter uses unsafe IERC20.approve instead of safeApprove on non-standard tokens"
    WIKI_DESCRIPTION = "Aave periphery adapters (ParaSwap buy/sell/liquidity-swap/repay) approve a spender for a user-provided token amount to route swaps through Augustus. The canonical pattern is `token.approve(spender, 0); token.approve(spender, amount);` to handle the 'approve race' requirement some tokens enforce. Pre-fix, these calls used `IERC20.approve` directly, which (a) does not check the boolean return value "
    WIKI_EXPLOIT_SCENARIO = "A user calls ParaSwapLiquiditySwapAdapter.swapAndDeposit specifying USDT as assetToSwapFrom. The adapter pulls USDT via flashloan or transferFrom, then `assetToSwapFrom.approve(tokenTransferProxy, 0)` — USDT returns void, solc-0.8 may or may not accept depending on the interface declaration. With `IERC20Detailed` (declared to return bool), the call compiles and at runtime either silently succeeds "
    WIKI_RECOMMENDATION = "Replace every `IERC20.approve` call in adapter contracts with `SafeERC20.safeApprove` (or OpenZeppelin 5.x `forceApprove`). Add `using SafeERC20 for IERC20Detailed;` at contract level. Keep the reset-to-0-then-amount sequence for compatibility with strict tokens. Audit every adapter (ParaSwap, Balan"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ParaSwap|augustus|Augustus|pool|POOL|Aave|AAVE'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '_buyOnParaSwap|_sellOnParaSwap|_swapAndDeposit|swapAndRepay|executeOperation|_repayWithCollateral|_swap'}, {'function.body_contains_regex': '\\.approve\\s*\\(\\s*(tokenTransferProxy|address\\(POOL\\)|address\\(pool\\)|spender|_spender)\\s*,\\s*0\\s*\\)'}, {'function.body_not_contains_regex': 'safeApprove|forceApprove'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-periphery-adapter-plain-approve-non-standard-erc20: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
