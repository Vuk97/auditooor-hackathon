"""
swap-inner-path-no-deadline — generated from reference/patterns.dsl/swap-inner-path-no-deadline.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py swap-inner-path-no-deadline.yaml
Source: solodit-cluster/missing-deadline-swap
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SwapInnerPathNoDeadline(AbstractDetector):
    ARGUMENT = "swap-inner-path-no-deadline"
    HELP = "Swap/trade entrypoint invokes a router without a deadline — tx replayable from the mempool and executable minutes/days later at an adverse price."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/swap-inner-path-no-deadline.yaml"
    WIKI_TITLE = "Missing deadline on AMM swap entrypoint"
    WIKI_DESCRIPTION = "A public function that forwards user funds into a router swap (UniV2 / UniV3 / 1inch-style) without specifying a deadline is executable long after the user's intended price window. Validators and searchers routinely delay inclusion of swap txs and execute them after the pool has moved against the user. This detector flags functions that call a router-style `.swap` / `swapExact*` / `IUniswapV2Route"
    WIKI_EXPLOIT_SCENARIO = "Protocol exposes `swapAndDeposit(amountIn, path)` which internally calls `IUniswapV2Router02(router).swapExactTokensForTokens(amountIn, minOut, path, address(this))` — no deadline argument. The transaction sits in the mempool through a volatility spike; a searcher rebroadcasts it hours later once the pool price is worse than `minOut` by a margin that still passes the slippage guard. The user's tra"
    WIKI_RECOMMENDATION = "Accept a caller-supplied `deadline` parameter on every swap surface and forward it verbatim into the router call. Reject deadlines that are more than a small margin (e.g. 30 min) beyond `block.timestamp`. Never pass `type(uint256).max` or `block.timestamp` itself as the deadline — the former disable"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'swap|swapExactTokens|trade|_swapInner|buy|sell|swapExactETH|swapExactFor'}, {'function.body_contains_regex': {'regex': 'router\\.swapExact|IRouter|IUniswapV2Router|IUniswapV3SwapRouter|swapRouter\\.|\\.swap\\s*\\('}}, {'function.body_not_contains_regex': 'deadline|block\\.timestamp\\s*\\+\\s*\\w+|type\\s*\\(\\s*uint256\\s*\\)\\.max|uint256\\s*\\(\\s*-1\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — swap-inner-path-no-deadline: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
