"""
c4-refund-requested-not-actual — generated from reference/patterns.dsl/c4-refund-requested-not-actual.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-refund-requested-not-actual.yaml
Source: code4arena/slice_ab-Superposition
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4RefundRequestedNotActual(AbstractDetector):
    ARGUMENT = "c4-refund-requested-not-actual"
    HELP = "Refund is computed from the requested / desired amount rather than the amount actually pulled or used. When the pool pulls less than requested, contract refunds the full requested amount — double-counting and draining contract liquidity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-refund-requested-not-actual.yaml"
    WIKI_TITLE = "Refund uses requested amount, not actual-transferred"
    WIKI_DESCRIPTION = "If a pool returns early because insufficient liquidity existed, the caller must refund only the portion that was NOT consumed. Refunding `amountDesired` (input) rather than `amountDesired - amountUsed` overpays by the unused portion's equivalent."
    WIKI_EXPLOIT_SCENARIO = "User calls `addLiquidity(1000)`. Pool only accepts 400 due to imbalance. Contract refunds `amountDesired = 1000`, effectively paying the user 600 from contract reserves. Attacker repeats, draining the contract."
    WIKI_RECOMMENDATION = "Refund exactly `amountDesired - amountUsed`. Compute `amountUsed` from the DEX return value, not the input."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'refund|residual|leftover|remaining'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(mint|addLiquidity|deposit|increaseLiquidity|provide|execute)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': 'refund|_refund|payable\\s*\\(\\s*\\w+\\s*\\)\\.transfer\\s*\\(|safeTransfer\\s*\\([^)]*,\\s*\\w+(amount|value)'}, {'function.body_contains_regex': '(amountDesired|requestedAmount|desiredAmount|amountIn)'}, {'function.body_not_contains_regex': '(amountUsed|actualAmount|amountIn\\s*-\\s*amountUsed|used\\s*=|pulled\\s*=|actualPulled)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-refund-requested-not-actual: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
