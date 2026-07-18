"""
deposit-failure-cancellation-uses-remaining-gas-not-original-fee — generated from reference/patterns.dsl/deposit-failure-cancellation-uses-remaining-gas-not-original-fee.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deposit-failure-cancellation-uses-remaining-gas-not-original-fee.yaml
Source: lisa-mine-r99-case-02117-sherlock-gmx-2023-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DepositFailureCancellationUsesRemainingGasNotOriginalFee(AbstractDetector):
    ARGUMENT = "deposit-failure-cancellation-uses-remaining-gas-not-original-fee"
    HELP = "Deposit / withdrawal handler measures keeper gas as `startingGas - gasleft()` after a try-catch on the inner execution call, then funds the cancellation path from whatever `gasleft()` remains. When `executeDeposit` reverts late (after consuming significant gas), the cancellation path is starved — it"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deposit-failure-cancellation-uses-remaining-gas-not-original-fee.yaml"
    WIKI_TITLE = "Deposit-failure cancel funds keeper from remaining gas, not the original execution fee"
    WIKI_DESCRIPTION = "Pattern fires on `executeDeposit` / `_handleDepositError` style handlers that snapshot `startingGas = gasleft()` at function entry, attempt the deposit logic, and on revert call `cancelDeposit(...)` while measuring used gas via `startingGas - gasleft()`. The cancellation flow then issues a keeper refund based on the leftover gas budget — but late-reverting `executeDeposit` paths consume most of th"
    WIKI_EXPLOIT_SCENARIO = "GMX user creates a deposit with 200k gas execution fee. `executeDeposit` runs; consumes 180k gas; reverts on a slippage check at the very end. The handler catches, calls `cancelDeposit` from inside the same external call. The cancellation path measures `startingGas - gasleft()` and refunds the keeper based on remaining 20k gas — far below the actual cost of the cancellation transaction (≈ 50k gas)"
    WIKI_RECOMMENDATION = "Reserve a fixed `cancellationGas` amount (e.g. 100k) at the start of `executeDeposit`. Wrap the inner deposit call in a sub-call with `gasleft() - cancellationGas` so the cancellation path is guaranteed to have its budget. Account for EIP-150's 63/64 rule when forwarding gas to subcalls. Pay the kee"

    _PRECONDITIONS = [{'contract.has_function_matching': 'executeDeposit|_handleDepositError|cancelDeposit|cancelWithdrawal'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'executeDeposit|_handleDepositError|_handleWithdrawalError|cancelDepositOnError|onExecuteDepositRevert'}, {'function.body_contains_regex': '\\b(startingGas|gasLimit|initialGas)\\s*(=|:=)\\s*gasleft\\s*\\(\\s*\\)|gasUsed\\s*=\\s*startingGas\\s*-\\s*gasleft\\s*\\(\\s*\\)'}, {'function.body_contains_regex': '_handleDepositError|cancelDeposit\\s*\\(|_cancelDeposit'}, {'function.body_not_contains_regex': 'reimburseExecutionFee|refundFullExecutionFee|cancellationGasReserve|reservedCancellationGas|gasleft\\s*\\(\\s*\\)\\s*\\*\\s*64\\s*\\/\\s*63'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deposit-failure-cancellation-uses-remaining-gas-not-original-fee: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
