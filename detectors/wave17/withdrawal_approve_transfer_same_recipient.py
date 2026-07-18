"""
withdrawal-approve-transfer-same-recipient — generated from reference/patterns.dsl/withdrawal-approve-transfer-same-recipient.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdrawal-approve-transfer-same-recipient.yaml
Source: reference/corpus_mined/slice_ag.md; detectors/wave6/approve_then_transfer_unspent.REPORT.md
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawalApproveTransferSameRecipient(AbstractDetector):
    ARGUMENT = "withdrawal-approve-transfer-same-recipient"
    HELP = "Withdrawal path both approves and transfers to the same recipient, leaving an unspent allowance that can be pulled later via transferFrom."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawal-approve-transfer-same-recipient.yaml"
    WIKI_TITLE = "Withdrawal approve plus transfer to the same recipient leaves a second-withdrawal allowance"
    WIKI_DESCRIPTION = "ERC20 approve() creates an allowance; transfer() and safeTransfer() do not consume it. A withdraw/claim/redeem path that calls both approve(recipient, amount) and transfer(recipient, amount) gives the recipient immediate funds and a still-live pull right for the same amount. That extra allowance can be exercised later when the contract has enough token balance."
    WIKI_EXPLOIT_SCENARIO = "A user calls withdraw(). The contract sends amount with token.transfer(msg.sender, amount) and also leaves token.approve(msg.sender, amount). The user receives the transfer, then later calls token.transferFrom(address(contract), msg.sender, amount) using the leftover allowance, pulling a second payout."
    WIKI_RECOMMENDATION = "Use one payout model. For push withdrawals, transfer or safeTransfer only. For pull withdrawals, approve only and do not also transfer. If approval is used for compatibility, clear it to zero after use and track claimed amounts so transferFrom cannot create a second claim."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC20|SafeERC20|approve|transfer|safeTransfer'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'withdraw|claim|redeem|release|disburse|exit'}, {'function.has_high_level_call_named': '^approve$'}, {'function.has_high_level_call_named': '^(transfer|safeTransfer)$'}, {'function.body_contains_regex': '(\\.approve\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,[\\s\\S]*\\.(?:transfer|safeTransfer)\\s*\\(\\s*\\2\\s*,|\\.(?:transfer|safeTransfer)\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,[\\s\\S]*\\.approve\\s*\\(\\s*\\3\\s*,)'}, {'function.body_not_contains_regex': '\\.approve\\s*\\(\\s*(msg\\.sender|recipient|user|account|to)\\s*,\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdrawal-approve-transfer-same-recipient: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
