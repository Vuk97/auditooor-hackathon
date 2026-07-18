"""
can-receiver-hook-returns-unchecked — generated from reference/patterns.dsl/can-receiver-hook-returns-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-receiver-hook-returns-unchecked.yaml
Source: cantina/2024-2025-hook-return-unchecked-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanReceiverHookReturnsUnchecked(AbstractDetector):
    ARGUMENT = "can-receiver-hook-returns-unchecked"
    HELP = "Receiver callback (onFlashLoan / onERC721Received / custom hook) invoked but return value discarded — integration step silently skipped, funds transferred anyway."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-receiver-hook-returns-unchecked.yaml"
    WIKI_TITLE = "Receiver hook return value unchecked"
    WIKI_DESCRIPTION = "Standards that use a callback return value as an integration acknowledgement (ERC-3156 flash loans return the hash of `ERC3156FlashBorrower.onFlashLoan(...)`, ERC-721 `onERC721Received` returns its selector) require the caller to compare the returned bytes against the expected magic value. If the caller discards the return, the receiver can implement the hook as a no-op while the outer call contin"
    WIKI_EXPLOIT_SCENARIO = "Cantina contest class: `flashLoan(receiver, amount, data)` transfers `amount` to `receiver`, calls `receiver.onFlashLoan(...)` but does not check the return value. A malicious receiver implements `onFlashLoan` as `return bytes32(0);`, does not repay, and the post-call `require(token.balanceOf(self) >= prevBal + fee)` either isn't present or is satisfied because the receiver diverted the balance ch"
    WIKI_RECOMMENDATION = "Capture and assert every callback return: `bytes32 ret = IERC3156FlashBorrower(receiver).onFlashLoan(msg.sender, token, amount, fee, data); require(ret == keccak256(\"ERC3156FlashBorrower.onFlashLoan\"), \"bad return\");`. For ERC-721/1155 receivers, use OpenZeppelin `_checkOnERC721Received`. Never "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'onFlashLoan|onERC|onTokenReceived|IFlashBorrower|IHook|callback'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(flashLoan|flashMint|_safeTransfer|_safeMint|executeHook|dispatch|notify|_notify|_callHook)'}, {'function.body_contains_regex': '\\.(onFlashLoan|onERC721Received|onERC1155Received|onTokenReceived|onDeposit|onCallback|hook|beforeAction|afterAction)\\s*\\('}, {'function.body_not_contains_regex': '==\\s*(keccak256|IERC\\w+\\.|I\\w+\\.|_?RETURN_?VALUE|_?CALLBACK_?SUCCESS|bytes32\\s*\\()'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-receiver-hook-returns-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
