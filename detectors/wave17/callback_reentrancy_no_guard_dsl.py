"""
callback-reentrancy-no-guard-dsl - generated from reference/patterns.dsl/callback_reentrancy_no_guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py callback_reentrancy_no_guard.yaml
Source: morpho/I2.B
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CallbackReentrancyNoGuardDsl(AbstractDetector):
    ARGUMENT = "callback-reentrancy-no-guard-dsl"
    HELP = "Callback-capable external transfer or hook call before accounting or settlement completes, with no shared reentrancy guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/callback_reentrancy_no_guard.yaml"
    WIKI_TITLE = "Callback reentrancy: state mutation after external call without guard"
    WIKI_DESCRIPTION = "Contracts that expose callback receiver surfaces must assume the counterparty can re-enter during a safe transfer, low-level value send, or protocol callback. The risky shape is not limited to local storage writes: settlement can also be incomplete when the callback runs before a payment pull or before order/accounting state is committed."
    WIKI_EXPLOIT_SCENARIO = "Attacker calls a deposit, fill, liquidation, or callback handler that transfers assets or calls an attacker-controlled hook before accounting or settlement is complete. The attacker re-enters through another public function while balances, order status, collateral movement, or repayment settlement are still in their pre-completion state."
    WIKI_RECOMMENDATION = "Apply a shared nonReentrant guard to the entrypoint and callback handler, or reorder to CEI so accounting and settlement complete before any callback-capable external control transfer. Suppress only when an inline guard or documented inverse-CEI ordering is present."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay)|IERC1155Receiver|IERC721Receiver|IERC777Recipient|ERC1155Holder|ERC1155TokenReceiver|ERC721Holder|IPreLiquidationCallback|IMorphoRepayCallback|safeTransferFrom|safeMint|tokensReceived)'}, {'contract.has_external_call_to': '(?i)^(safeTransferFrom|safeTransfer|safeMint|tokensReceived|onERC721Received|onERC1155Received|onERC1155BatchReceived|onPreLiquidate|onLiquidate|onMorphoRepay|call|send|transfer)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^_?(deposit|withdraw|redeem|borrow|repay|liquidate|preLiquidate|fill|match|execute|buy|purchase|claim|cancel|mint|burn|on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay))[A-Za-z0-9_]*$'}, {'function.body_ordered_regex': {'first': '(?i)(safeTransferFrom\\s*\\(|safeTransfer\\s*\\(|safeMint\\s*\\(|tokensReceived\\s*\\(|onERC721Received\\s*\\(|onERC1155Received\\s*\\(|onERC1155BatchReceived\\s*\\(|onPreLiquidate\\s*\\(|onLiquidate\\s*\\(|onMorphoRepay\\s*\\(|\\.on[A-Za-z0-9_]*(Received|Callback|Liquidate|Repay)\\s*\\(|\\.call\\s*(?:\\{|\\.value\\s*\\(|\\s*\\()|\\.transfer\\s*\\(|\\.send\\s*\\()', 'second': '(?i)((balance|balances|share|shares|debt|borrow|collateral|filled|remaining|status|order|orders|claim|position|reward|total[A-Z][A-Za-z0-9_]*)\\s*(?:\\[[^\\]]+\\])?\\s*(?:=|\\+=|-=|\\+\\+|--)|safeTransferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower)\\b|transferFrom\\s*\\([^)]*\\b(liquidator|msg\\.sender|caller|borrower)\\b|emit\\s+(OrderFilled|Deposit|Withdraw|Liquidate|Claim|Transfer))', 'ignore_comments_and_strings': True}}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'noReentrancy', 'nonreentrant'], 'negate': True}}, {'function.body_not_contains_regex': '(?i)\\bnonReentrant\\b|ReentrancyGuard|_reentrancyGuardEntered|_status\\s*=\\s*_ENTERED|locked\\s*=\\s*true|reentrancyLock|noReentrancy'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|_assertNotERC777|checkNotInVaultContext|readonlyReentrancy|super\\.(deposit|withdraw|redeem))'}]

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
                info = [f, f" - callback-reentrancy-no-guard-dsl: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
