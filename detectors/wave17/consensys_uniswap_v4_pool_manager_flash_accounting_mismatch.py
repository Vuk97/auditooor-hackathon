"""
consensys-uniswap-v4-pool-manager-flash-accounting-mismatch — generated from reference/patterns.dsl/consensys-uniswap-v4-pool-manager-flash-accounting-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py consensys-uniswap-v4-pool-manager-flash-accounting-mismatch.yaml
Source: auditooor-R75-consensys-uniswap-v4-integrator-HIGH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConsensysUniswapV4PoolManagerFlashAccountingMismatch(AbstractDetector):
    ARGUMENT = "consensys-uniswap-v4-pool-manager-flash-accounting-mismatch"
    HELP = "Uniswap v4 integrator settles/takes using locally cached delta rather than poolManager.currencyDelta(). Hook-induced delta changes are missed, leaving the pool debited or the integrator short."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/consensys-uniswap-v4-pool-manager-flash-accounting-mismatch.yaml"
    WIKI_TITLE = "v4 unlockCallback settles against stale integrator-side delta, not PoolManager truth"
    WIKI_DESCRIPTION = "Uniswap v4's flash accounting requires integrators to close out currency deltas before `unlock()` returns. The canonical way to read the outstanding delta is `poolManager.currencyDelta(msg.sender, currency)`, which reflects every hook-driven mutation. Integrators that instead pass a pre-hook computed `amount` to `settle` / `take` diverge from the manager's view whenever a hook (or a multi-swap rou"
    WIKI_EXPLOIT_SCENARIO = "Router holds intended amounts a0, a1 from user. It calls swap which triggers a malicious hook the user supplied (v4 allows user-supplied hooks for custom pools). Hook does a nested swap that alters the router's delta by +dx on currency0. Router then settles a0 (stale) and takes a1 (stale). `PoolManager` sees delta = a0 - dx unsettled; the tx reverts at unlock's final check OR, in the mirror case w"
    WIKI_RECOMMENDATION = "Always compute the settle/take amount from `poolManager.currencyDelta(msg.sender, currency)` right before the call. Treat the integrator-side computed amount as an upper bound / sanity check only, not as the source of truth. Add a post-condition: after the loop of settles/takes, `poolManager.currenc"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'unlockCallback|_unlockCallback'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(unlockCallback|_unlockCallback)$'}, {'function.body_contains_regex': '(settle|take)\\s*\\([^)]*,\\s*(amount|delta)\\s*\\)'}, {'function.body_not_contains_regex': 'poolManager\\.currencyDelta|manager\\.currencyDelta|getCurrencyDelta'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — consensys-uniswap-v4-pool-manager-flash-accounting-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
