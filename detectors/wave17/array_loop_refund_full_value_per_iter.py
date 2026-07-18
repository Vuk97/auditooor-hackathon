"""
array-loop-refund-full-value-per-iter — generated from reference/patterns.dsl/array-loop-refund-full-value-per-iter.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py array-loop-refund-full-value-per-iter.yaml
Source: defihacklabs/SynapLogic_2026-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArrayLoopRefundFullValuePerIter(AbstractDetector):
    ARGUMENT = "array-loop-refund-full-value-per-iter"
    HELP = "Bulk-action entry point loops over a user-supplied `recipients[] / rates[]` array and refunds `msg.value * rate / 100` per iteration without decrementing a running balance. One call with N iterations at rate 10% refunds N * 10% of msg.value — attacker sets N large enough to drain the contract (Synap"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/array-loop-refund-full-value-per-iter.yaml"
    WIKI_TITLE = "Bulk-refund loop multiplies msg.value refund per iteration"
    WIKI_DESCRIPTION = "A sale / claim / settlement contract exposes a bulk entry point like `buy(address[] recipients, uint256[] rates, bool[] refundFlags)`. Inside the loop each iteration refunds `msg.value * rate / 100` to the recipient when the refund flag is set. Because the loop never decrements a `remaining` counter, a single call with N iterations at rate 10% refunds N * 10% of msg.value. The attacker sets N so t"
    WIKI_EXPLOIT_SCENARIO = "SynapLogic sale proxy: attacker calls `buy{value: 1 ETH}(recipients=[attacker]*N, rates=[10]*N, refundFlags=[true]*N)` with N = saleBalance / (1 ETH * 10/100). Each iteration of the internal loop runs `recipients[i].call{value: msg.value * rate / 100}` without any `remaining -= refund` bookkeeping. After N iterations the attacker has received N * 0.1 ETH — bounded only by the contract's total ETH "
    WIKI_RECOMMENDATION = "Compute the per-iteration payout from a running `remaining` balance that starts at msg.value (or the pulled ERC-20 amount) and decrements on each disbursement; revert if any iteration would push remaining below zero. Alternatively, compute the total refund upfront (`sum(rates) * msg.value / 100`) an"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'array'}, {'function.body_contains_regex': {'regex': 'for\\s*\\(\\s*uint'}}, {'function.body_contains_regex': {'regex': '(transfer|call\\{value:|_safeTransfer)\\s*\\(.*(msg\\.value|amount)\\s*\\*\\s*(rate|ratio|bps|percent)'}}, {'function.body_not_contains_regex': '(remaining|totalRefunded|totalDistributed|totalOut|distributed)\\s*-=|\\bremaining\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — array-loop-refund-full-value-per-iter: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
