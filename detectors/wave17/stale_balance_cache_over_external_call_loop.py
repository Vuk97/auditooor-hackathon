"""
stale-balance-cache-over-external-call-loop — generated from reference/patterns.dsl/stale-balance-cache-over-external-call-loop.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stale-balance-cache-over-external-call-loop.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StaleBalanceCacheOverExternalCallLoop(AbstractDetector):
    ARGUMENT = "stale-balance-cache-over-external-call-loop"
    HELP = "Function caches balanceOf before a loop that performs external calls. The cached value becomes stale after the first iteration, letting later iterations over-distribute or miss mutations."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stale-balance-cache-over-external-call-loop.yaml"
    WIKI_TITLE = "Balance cached before external-call loop becomes stale"
    WIKI_DESCRIPTION = "Looping distributions over an external-call boundary must refresh any balance caches between iterations. A single cached `balanceOf(this)` read before the loop will not reflect state changes from prior iterations or reentrant callbacks, leading to over-distribution or double-counting."
    WIKI_EXPLOIT_SCENARIO = "Protocol distributes `token.balanceOf(this)` pro-rata to N strategies in one loop. Cached `total = token.balanceOf(this)` before loop. Iteration 1 transfers `total/N` to strategy1 — real balance drops. Iteration 2 still reads `total` from cache and tries to transfer the same `total/N`, but real balance is `total - total/N`. On strategy K, transfer exceeds actual balance and reverts OR double-count"
    WIKI_RECOMMENDATION = "Refresh the balance inside each iteration: `uint256 available = token.balanceOf(address(this));`. Or, compute shares in a pure read-only loop first and commit all transfers in a second loop."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|balanceOf|safeTransfer'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.external_call_count_gte': 2}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(uint256|uint128)\\s+\\w+\\s*=\\s*\\w*\\.balanceOf\\s*\\(|\\b_balance\\s*=\\s*\\w+\\.balanceOf'}, {'function.body_contains_regex': 'for\\s*\\(|while\\s*\\('}, {'function.body_not_contains_regex': '\\.balanceOf\\s*\\([^)]*\\)\\s*(?=[^{]*for)|refreshBalance|_updateBalance|balanceAfter\\s*='}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — stale-balance-cache-over-external-call-loop: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
