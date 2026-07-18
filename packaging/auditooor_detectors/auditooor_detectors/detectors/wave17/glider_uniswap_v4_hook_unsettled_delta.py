"""
glider-uniswap-v4-hook-unsettled-delta — generated from reference/patterns.dsl/glider-uniswap-v4-hook-unsettled-delta.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-uniswap-v4-hook-unsettled-delta.yaml
Source: glider/uniswap-v4-hook-unsettled-delta
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderUniswapV4HookUnsettledDelta(AbstractDetector):
    ARGUMENT = "glider-uniswap-v4-hook-unsettled-delta"
    HELP = "Uniswap V4 hook exits unlock callback without calling settle/take — delta leaks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-uniswap-v4-hook-unsettled-delta.yaml"
    WIKI_TITLE = "Uniswap V4 hook leaves BalanceDelta unsettled"
    WIKI_DESCRIPTION = "V4's flash-accounting model allows any address that has received a positive delta to `take` assets, and any owing a negative delta must `settle` them before the lock releases. A hook that performs a swap but forgets to settle leaves accounting in an inconsistent state, causing the outer `unlock` to revert or funds to become claimable by the hook."
    WIKI_EXPLOIT_SCENARIO = "Custom `afterSwap` hook computes a fee, mints protocol ERC20 in return, but forgets `poolManager.settle(currency)` for the fee amount. When the outer lock releases, the pool's solvency check fails — either reverting all legitimate swaps (DOS) or, if the hook also calls `take` first, letting attacker steal the fee amount."
    WIKI_RECOMMENDATION = "Every hook path that touches pool balances must call `poolManager.settle` for owed deltas and `poolManager.take` for owed-to deltas before returning. Use OZ `CurrencySettler` library for the canonical pattern."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IHooks|afterSwap|beforeSwap|unlockCallback|IPoolManager'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(unlockCallback|lockAcquired|afterSwap|beforeSwap|afterAddLiquidity|afterRemoveLiquidity)$'}, {'function.body_contains_regex': 'BalanceDelta|delta\\s*=|poolManager\\.swap|manager\\.swap'}, {'function.body_not_contains_regex': '\\.settle\\s*\\(|\\.take\\s*\\(|_settleDeltas|CurrencySettler'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-uniswap-v4-hook-unsettled-delta: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
