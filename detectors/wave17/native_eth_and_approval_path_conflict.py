"""
native-eth-and-approval-path-conflict — generated from reference/patterns.dsl/native-eth-and-approval-path-conflict.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py native-eth-and-approval-path-conflict.yaml
Source: auditooor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NativeEthAndApprovalPathConflict(AbstractDetector):
    ARGUMENT = "native-eth-and-approval-path-conflict"
    HELP = "Payable entry-point accepts both msg.value AND pulls pre-approved tokens via transferFrom without mutually excluding the two code paths — attacker double-deposits."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/native-eth-and-approval-path-conflict.yaml"
    WIKI_TITLE = "Payable function also pulls pre-approved tokens without XOR gating the native and ERC20 paths"
    WIKI_DESCRIPTION = "A payable external function accepts native ETH via msg.value and, in the same body, pulls pre-approved tokens from the caller via transferFrom. Both payment paths execute unconditionally, so a caller who sends N wei of ETH AND pre-approves N of the wrapped token receives credit for 2N. The two paths must be mutually exclusive (e.g. require(msg.value == 0) in the approval branch, or an explicit isN"
    WIKI_EXPLOIT_SCENARIO = "A deposit/zap function is `payable` and internally wraps msg.value into WETH while also calling `weth.transferFrom(msg.sender, address(this), amount)`. The user pre-approves `amount` WETH, then calls the function with `{value: amount}`. The contract wraps the ETH (balance grows by `amount`) AND pulls `amount` more WETH from the user, but only credits the caller once for `amount`. The attacker now "
    WIKI_RECOMMENDATION = "Enforce an XOR between the native and ERC20 payment paths. Either require `msg.value == 0` when the approval path is used (or `amount == 0` when the native path is used), or route on an explicit `isNativePayment` / `PaymentType` switch and early-revert the other branch. For wrapped-native wrappers, "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_payable': True}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '\\.transferFrom\\s*\\(\\s*msg\\.sender|safeTransferFrom\\s*\\(\\s*msg\\.sender|\\.transferFrom\\s*\\(\\s*user'}, {'function.body_not_contains_regex': 'msg\\.value\\s*==\\s*0|msg\\.value\\s*!=\\s*0|\\?\\s*.*msg\\.value.*:|require\\s*\\(\\s*(msg\\.value|amount)\\s*==\\s*0|isNativePayment'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — native-eth-and-approval-path-conflict: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
