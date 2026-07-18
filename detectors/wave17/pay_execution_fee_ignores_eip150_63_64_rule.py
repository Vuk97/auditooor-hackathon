"""
pay-execution-fee-ignores-eip150-63-64-rule — generated from reference/patterns.dsl/pay-execution-fee-ignores-eip150-63-64-rule.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pay-execution-fee-ignores-eip150-63-64-rule.yaml
Source: lisa-mine-r99-case-01819-sherlock-gmx-2023-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PayExecutionFeeIgnoresEip1506364Rule(AbstractDetector):
    ARGUMENT = "pay-execution-fee-ignores-eip150-63-64-rule"
    HELP = "External `payExecutionFee` function measures keeper gas cost as `gasUsed = startingGas - gasleft()` and reimburses the keeper, but the function itself makes external calls (or is called from an external context) where EIP-150 reserves 1/64 of gas to the caller. The keeper's measured `gasUsed` overst"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pay-execution-fee-ignores-eip150-63-64-rule.yaml"
    WIKI_TITLE = "payExecutionFee uses startingGas - gasleft() ignoring EIP-150 63/64 subcall rule"
    WIKI_DESCRIPTION = "Pattern fires on `payExecutionFee` style external functions that snapshot `startingGas = gasleft()` at entry, perform external work, and at exit compute `gasUsed = startingGas - gasleft()` for keeper reimbursement. Because the function itself was entered via an external call, EIP-150 retained 1/64 of the caller's gas for the caller — meaning `startingGas` already lost 1/64. Internal subcalls withi"
    WIKI_EXPLOIT_SCENARIO = "GMX user pre-pays an execution fee assuming a worst-case 200k gas budget. Keeper executes the order; actual gas consumed is 100k. `payExecutionFee` measures `startingGas - gasleft()` = ~98.4k (because EIP-150 1/64 was already lost on entry). Keeper is reimbursed 98.4k * gas_price even though the keeper actually paid 100k * gas_price for the inner work. Over many executions, the difference accumula"
    WIKI_RECOMMENDATION = "Adjust for EIP-150's 63/64 rule: `uint256 adjusted = (startingGas - gasleft()) * 64 / 63;` (this approximates the gas the caller's frame actually lost). For nested subcalls, apply the adjustment recursively or fix the keeper reimbursement at a flat per-action cap that the protocol calibrates against"

    _PRECONDITIONS = [{'contract.has_function_matching': 'payExecutionFee|payKeeperFee|reimburseExecutionFee|claimExecutionFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(payExecutionFee|payKeeperFee|reimburseExecutionFee|_payExecutionFee)$'}, {'function.body_contains_regex': '\\bgasUsed\\s*=\\s*startingGas\\s*-\\s*gasleft\\s*\\(\\s*\\)|\\bgasUsed\\s*=\\s*startGas\\s*-\\s*gasleft\\s*\\(\\s*\\)|gasleft\\s*\\(\\s*\\)\\s*<\\s*startingGas'}, {'function.has_external_call': True}, {'function.body_not_contains_regex': '\\*\\s*64\\s*\\/\\s*63|\\*\\s*63\\s*\\/\\s*64|/\\s*63\\s*\\*\\s*64|gasleft\\s*\\(\\s*\\)\\s*\\*\\s*63\\s*\\/\\s*64|EIP[_-]?150|adjustForSubcall|gasForSubcall'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — pay-execution-fee-ignores-eip150-63-64-rule: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
