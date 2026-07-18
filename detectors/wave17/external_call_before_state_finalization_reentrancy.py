"""
external-call-before-state-finalization-reentrancy - generated from reference/patterns.dsl/external-call-before-state-finalization-reentrancy.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py external-call-before-state-finalization-reentrancy.yaml
Source: realworld-recall-gap:p1-reentrancy:morpho-preliquidation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ExternalCallBeforeStateFinalizationReentrancy(AbstractDetector):
    ARGUMENT = "external-call-before-state-finalization-reentrancy"
    HELP = "External call, token hook, or protocol callback fires before accounting or settlement finalizes, with no shared reentrancy guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/external-call-before-state-finalization-reentrancy.yaml"
    WIKI_TITLE = "Callback or external call before final state enables reentrancy"
    WIKI_DESCRIPTION = "The risky shape is an externally callable mutating entry point that transfers control to an attacker-controlled receiver, hook, callback, or payable fallback before the function has finalized balances, debt, collateral, order status, settlement, nonce, or payment-pull state. The external target can re-enter a sibling entry point while the protocol still exposes a partially updated or not-yet-settl"
    WIKI_EXPLOIT_SCENARIO = "A liquidator callback fires after collateral leaves a borrower but before repayment is pulled, or a flash loan callback fires before fee/debt state is written, or a token hook fires before deposit accounting is committed. The attacker re-enters through the callback and repeats the action or reads stale state before the outer call reaches its finalization step."
    WIKI_RECOMMENDATION = "Apply one shared reentrancy guard across the entry point and callback handler, or reorder to CEI so the final accounting, settlement, nonce, debt, and payment-pull state is complete before any external control transfer. If a callback must precede payment for flash settlement, use a per-account or pe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(callback|on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan)|safeTransferFrom|transferFrom|\\.call\\s*(\\{|\\.value|\\()|\\.transfer\\s*\\(|\\.send\\s*\\()'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(deposit|withdraw|redeem|borrow|repay|liquidate|preLiquidate|settle|fill|match|execute|buy|purchase|claim|cancel|mint|burn|refund|flash|flashLoan|on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan))[A-Za-z0-9_]*$'}, {'function.body_ordered_regex': {'first': '(?i)(\\.on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan)\\s*\\(|\\bon[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay|FlashLoan)\\s*\\(|safeTransferFrom\\s*\\(|safeTransfer\\s*\\(|transferFrom\\s*\\(|\\.call\\s*(?:\\{|\\.value\\s*\\(|\\s*\\()|\\.transfer\\s*\\(|\\.send\\s*\\()', 'second': '(?i)((balance|balances|account|accounts|share|shares|debt|borrow|collateral|position|positions|filled|remaining|status|order|orders|claim|claimed|reward|rewards|total[A-Z][A-Za-z0-9_]*|reserve|index|nonce|owed|paid|settled|finalized)\\s*(?:\\[[^\\]]+\\])?(?:\\.[A-Za-z0-9_]+)?\\s*(?:=|\\+=|-=|\\+\\+|--)|\\bdelete\\s+(balance|balances|account|accounts|debt|borrow|collateral|position|positions|order|orders|claim|claimed|nonce)[A-Za-z0-9_\\[\\]\\.]*|safeTransferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower|payer|receiver)\\b|transferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower|payer|receiver)\\b|emit\\s+(Deposit|Withdraw|Redeem|Borrow|Repay|Liquidate|Claim|Fill|Settle|Transfer))', 'ignore_comments_and_strings': True}}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'noReentrancy', 'nonreentrant'], 'negate': True}}, {'function.body_not_contains_regex': '(?i)\\bnonReentrant\\b|ReentrancyGuard|_reentrancyGuardEntered|_status\\s*=\\s*_ENTERED|locked\\s*=\\s*true|reentrancyLock|noReentrancy'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|_assertNotERC777|checkNotInVaultContext|readonlyReentrancy|super\\.(deposit|withdraw|redeem))'}]

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
                info = [f, f" - external-call-before-state-finalization-reentrancy: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
