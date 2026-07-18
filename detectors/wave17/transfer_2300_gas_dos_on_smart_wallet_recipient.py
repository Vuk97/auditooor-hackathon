"""
transfer-2300-gas-dos-on-smart-wallet-recipient — generated from reference/patterns.dsl/transfer-2300-gas-dos-on-smart-wallet-recipient.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transfer-2300-gas-dos-on-smart-wallet-recipient.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-612
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Transfer2300GasDosOnSmartWalletRecipient(AbstractDetector):
    ARGUMENT = "transfer-2300-gas-dos-on-smart-wallet-recipient"
    HELP = "ETH claim uses .transfer (2300 gas) while caller must equal original requester, permanently locking funds for smart-wallet users."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transfer-2300-gas-dos-on-smart-wallet-recipient.yaml"
    WIKI_TITLE = "ETH claim with .transfer() and requester-bound caller DoSes multisig / smart-wallet withdrawers"
    WIKI_DESCRIPTION = "When a claim function (a) forwards ETH with Solidity's `.transfer()` — capped at 2300 gas — and (b) requires `msg.sender` to equal the stored requester, smart-wallet users whose receive() consumes more than 2300 gas are permanently locked out. Safe wallets, Argent, Gnosis Safe, and any wallet that emits events or updates storage on receive cost 6–30k gas. Because no other address can claim on the "
    WIKI_EXPLOIT_SCENARIO = "A Safe multisig calls `WithdrawQueue.withdraw()`. 7 days later it calls `claim()`; the queue does `payable(msg.sender).transfer(10 ether)`. The Safe proxy's receive() needs ~6800 gas — transfer() reverts every time. The 10 ETH is stuck forever."
    WIKI_RECOMMENDATION = "Replace `.transfer()` with `.call{value: x}(\"\")` and check the boolean return. If the caller-must-equal-requester invariant is important for accounting, add an explicit `recipient` parameter at request time so users can nominate a different address for delivery."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(claim|withdraw|redeem|unstake|exit|completeWithdrawal)'}, {'function.body_contains_regex': 'payable\\s*\\(\\s*[^)]+\\)\\s*\\.transfer\\s*\\('}, {'function.body_contains_regex': '(?i)(msg\\.sender\\s*==|require\\s*\\(\\s*.*requester\\s*==|onlyRequester|\\.recipient\\s*==\\s*msg\\.sender)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, "!function.body_contains_regex: '\\.call\\{\\s*value'", {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transfer-2300-gas-dos-on-smart-wallet-recipient: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
