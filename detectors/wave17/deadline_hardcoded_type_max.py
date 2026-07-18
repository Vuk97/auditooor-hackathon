"""
deadline-hardcoded-type-max — generated from reference/patterns.dsl/deadline-hardcoded-type-max.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deadline-hardcoded-type-max.yaml
Source: solodit/sherlock/blueberry-H14-18494
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DeadlineHardcodedTypeMax(AbstractDetector):
    ARGUMENT = "deadline-hardcoded-type-max"
    HELP = "AMM swap / mint / burn call passes `type(uint256).max` as the deadline, disabling the router's freshness check. Stuck mempool txs execute hours later against stale slippage, inviting MEV sandwiches."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deadline-hardcoded-type-max.yaml"
    WIKI_TITLE = "Swap deadline hardcoded to `type(uint256).max` — stale slippage MEV sandwich"
    WIKI_DESCRIPTION = "AMM routers accept a `deadline` timestamp argument to revert transactions that sit too long in the mempool, protecting users from executing stale slippage. When a caller passes `type(uint256).max` (or any other sentinel that never expires), the guard is effectively removed. A transaction with tight slippage at signing time (e.g., sqrtPriceLimit matching the current tick) becomes loose when market "
    WIKI_EXPLOIT_SCENARIO = "CurveSpell.claimRewards swaps harvested CRV to the debt token via `swapExactTokensForTokens(rewards, 0, path, self, type(uint256).max)`. A keeper sends the tx in a low-gas period. Block builder delays inclusion by 20 minutes. During the window, CRV price moves 2%; an MEV searcher detects the stale tx with `minOut=0`, front-runs to move the pool further, then back-runs to close. Protocol's rewards "
    WIKI_RECOMMENDATION = "Always pass `block.timestamp + smallWindow` (e.g., +300) as the deadline. Accept deadline as a caller parameter (bounded) rather than hard-coding. Never use `type(uint256).max` or other never-expiring sentinels. Additionally, never pair a hardcoded deadline with `minOut=0`; if slippage must be permi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.body_contains_regex': 'swapExact|swapTokensForExact|exactInput|exactOutput|addLiquidity|removeLiquidity'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.body_contains_regex': '(swapExact\\w+|swapTokensForExact\\w+|exactInput\\w*|exactOutput\\w*|addLiquidity\\w*|removeLiquidity\\w*)\\s*\\('}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': 'type\\s*\\(\\s*uint256\\s*\\)\\s*\\.\\s*max|type\\s*\\(\\s*uint\\s*\\)\\s*\\.\\s*max|0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff|block\\.timestamp\\s*\\+\\s*(1e18|type\\s*\\(\\s*uint)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deadline-hardcoded-type-max: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
