"""
refund-computed-after-external-call-stale — generated from reference/patterns.dsl/refund-computed-after-external-call-stale.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py refund-computed-after-external-call-stale.yaml
Source: solodit-cluster/R34
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RefundComputedAfterExternalCallStale(AbstractDetector):
    ARGUMENT = "refund-computed-after-external-call-stale"
    HELP = "Function performs an external swap/borrow, then reads `actualSpent` from an external getter AFTER the call to compute `refund = provided - actualSpent`. With a reentrant token the attacker can mutate the getter between call-return and read, producing a stale / attacker-chosen `actualSpent` and skewi"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/refund-computed-after-external-call-stale.yaml"
    WIKI_TITLE = "Refund computed from post-call external getter is stale under reentrancy"
    WIKI_DESCRIPTION = "A public/external path (swap, repay, settle) accepts a user-supplied `providedAmount`, calls an external contract to execute the operation, then reads an external getter (e.g., `token.balanceOf(address(this))` wrapped in another contract's accessor, or a router's `amountsOut`) AFTER the call to determine `actualSpent`. The refund is then `refund = providedAmount - actualSpent`. If the external tar"
    WIKI_EXPLOIT_SCENARIO = "A margin vault's repay() calls `router.swap(providedAmount, ...)`. On swap return the vault calls `router.lastSpent()` to determine actualSpent. The router reads its own internal accounting which the attacker mutated via a hook in the swap-token's transfer (the swap-token is ERC777). `lastSpent` returns a value the attacker chose (e.g., 0), the vault persists `refund = providedAmount - 0 = provide"
    WIKI_RECOMMENDATION = "Snapshot the relevant balance/accounting BEFORE the external call (`uint256 balanceBefore = token.balanceOf(address(this));`) and compute `actualSpent = balanceBefore - token.balanceOf(address(this))` from locally-held values. Never trust a post-call external getter. If the external getter is unavoi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(refund|escrow|pending|deposit)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_external_call': True}, {'function.post_external_call_writes_gte': 1}, {'function.body_contains_regex': 'refund\\s*=|_refund\\s*=|excess\\s*=|surplus\\s*=|remaining\\s*='}, {'function.body_not_contains_regex': 'balanceBefore|_balanceBefore|initialBalance|preBalance|snapshotBefore'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — refund-computed-after-external-call-stale: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
