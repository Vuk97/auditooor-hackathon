"""
dex-aggregator-funds-lost-on-silent-revert — generated from reference/patterns.dsl/dex-aggregator-funds-lost-on-silent-revert.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dex-aggregator-funds-lost-on-silent-revert.yaml
Source: auditooor-R75-code4rena-2024-06-thorchain-16
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DexAggregatorFundsLostOnSilentRevert(AbstractDetector):
    ARGUMENT = "dex-aggregator-funds-lost-on-silent-revert"
    HELP = "Router transfers tokens to aggregator then calls swap with .call — on revert tokens are stuck; no refund logic in the failure branch."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dex-aggregator-funds-lost-on-silent-revert.yaml"
    WIKI_TITLE = "Router forwards tokens to aggregator and ignores swap failure, losing user funds to the aggregator"
    WIKI_DESCRIPTION = "`_transferOutAndCallV5` transfers `aggregationPayload.fromAmount` of ERC20 to `aggregationPayload.target`, then calls `target.swapOutV5(...)` via `.call{value:0}`. The design intent is 'if aggregator fails, don't revert the outer tx'. But tokens are already gone: failure means they sit in the aggregator contract with no on-chain method for the user or router to retrieve them. Recipient receives no"
    WIKI_EXPLOIT_SCENARIO = "User initiates swap: 1000 USDC → aggregator → ETH for recipient. Router transfers 1000 USDC to aggregator. Aggregator's internal swap reverts because of slippage (`amountOutMin` not met). The call returns `_dexAggSuccess = false` but _transferOutAndCallV5 proceeds without reverting. User's 1000 USDC is now stuck in the aggregator contract."
    WIKI_RECOMMENDATION = "Either (a) revert on swap failure so tokens are rolled back by the transfer; or (b) if graceful failure is desired, query balance pre/post and pull unused tokens back from the aggregator (requires aggregator to approve back). Cleanest: use try/catch and on failure, attempt refund then revert with a "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal_or_private'}, {'function.name_matches': '(?i)_transferOutAndCall\\w*|transferAndSwap|_forwardToAggregator'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '(?i)\\.call\\s*\\{value:\\s*0\\}\\s*\\('}, {'function.body_contains_regex': '(?i)bool\\s+_?\\w*Success\\s*,|bool\\s+dexSuccess'}, {'function.body_contains_regex': '(?i)transfer\\s*\\(\\s*(address,\\s*uint256)?|safeTransfer'}, {'function.body_not_contains_regex': '(?i)if\\s*\\(\\s*!\\s*\\w*Success\\s*\\)\\s*\\{[^}]*transfer|require\\s*\\(\\s*\\w*Success|_refund'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dex-aggregator-funds-lost-on-silent-revert: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
