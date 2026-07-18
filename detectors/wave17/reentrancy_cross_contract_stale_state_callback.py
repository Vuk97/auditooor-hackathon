"""
reentrancy-cross-contract-stale-state-callback - generated from reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reentrancy-cross-contract-stale-state-callback.yaml
Source: capability-lift:P1-08:reentrancy-cross-contract
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReentrancyCrossContractStaleStateCallback(AbstractDetector):
    ARGUMENT = "reentrancy-cross-contract-stale-state-callback"
    HELP = "A callback, hook, token transfer, receiver call, liquidation callback, or adapter call occurs before debt/accounting/status/allowance/state finalization, with no shared reentrancy guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml"
    WIKI_TITLE = "Cross-contract callback before finalization enables stale-state reentrancy"
    WIKI_DESCRIPTION = "The dangerous shape is an externally callable mutating path that transfers control to a callback, hook, token receiver, adapter, or payable fallback before finalizing debt, accounting, status, allowance, nonce, settlement, or position state. The external target can reenter through a sibling function or callback while the protocol still exposes stale state."
    WIKI_EXPLOIT_SCENARIO = "A pre-liquidation callback fires after collateral movement but before repayment is pulled, a token transfer hook fires before deposit accounting is committed, or an adapter callback fires before settlement status is marked complete. The attacker reenters through another public function and consumes stale accounting or repeats a per-call capped action before the outer function finalizes."
    WIKI_RECOMMENDATION = "Use a shared reentrancy guard across entrypoints and callback handlers, or reorder to checks-effects-interactions so final state is committed before any external control transfer. When a callback must precede payment settlement, add a per-account or per-position same-transaction lock that blocks sib"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(callback|hook|adapter|receiver|safeTransferFrom|safeTransfer|transferFrom|on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan|Settle)|\\.call\\s*(?:\\{|\\(|\\.value)|\\.transfer\\s*\\(|\\.send\\s*\\()'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(deposit|withdraw|redeem|borrow|repay|liquidate|preLiquidate|settle|fill|match|execute|buy|purchase|claim|cancel|mint|burn|refund|flash|flashLoan|callback|on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan|Settle))[A-Za-z0-9_]*$'}, {'function.body_ordered_regex': {'first': '(?i)(\\bI[A-Za-z0-9_]*(Callback|Hook|Receiver|Adapter)\\s*\\([^)]*\\)\\s*\\.[A-Za-z0-9_]+\\s*\\(|\\.[A-Za-z0-9_]*(Callback|Hook|Receiver|Adapter)\\s*\\(|\\.on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan|Settle)\\s*\\(|\\bon[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan|Settle)\\s*\\(|safeTransferFrom\\s*\\(|safeTransfer\\s*\\(|transferFrom\\s*\\(|\\.call\\s*(?:\\{|\\(|\\.value\\s*\\()|\\.transfer\\s*\\(|\\.send\\s*\\()', 'second': '(?i)(\\b(debt|debts|borrow|borrowed|accounting|accounted|balance|balances|share|shares|status|state|allowance|allowed|approval|approved|nonce|nonces|position|positions|collateral|settled|settlement|finalized|finalised|filled|remaining|owed|paid|claim|claimed|reward|rewards|total[A-Z][A-Za-z0-9_]*)\\s*(?:\\[[^\\]]+\\])?(?:\\.[A-Za-z0-9_]+)?\\s*(?:=|\\+=|-=|\\+\\+|--)|\\bdelete\\s+(debt|borrow|balance|balances|allowance|approval|nonce|position|collateral|claim|reward)[A-Za-z0-9_\\[\\]\\.]*|\\bsafeTransferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower|payer|receiver|owner)\\b|\\btransferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower|payer|receiver|owner)\\b|emit\\s+(Deposit|Withdraw|Redeem|Borrow|Repay|Liquidate|Claim|Fill|Settle|Status|Transfer))', 'ignore_comments_and_strings': True}}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'noReentrancy', 'nonreentrant'], 'negate': True}}, {'function.body_not_contains_regex': '(?i)\\bnonReentrant\\b|ReentrancyGuard|_reentrancyGuardEntered|_status\\s*=\\s*_ENTERED|locked\\s*=\\s*true|reentrancyLock|noReentrancy|_entered\\s*=\\s*true'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|readonlyReentrancy|checkNotInVaultContext|super\\.(deposit|withdraw|redeem))'}]

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
                info = [f, f" - reentrancy-cross-contract-stale-state-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
