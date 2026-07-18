"""
deposit-accepts-excess-native-eth — generated from reference/patterns.dsl/deposit-accepts-excess-native-eth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py deposit-accepts-excess-native-eth.yaml
Source: solodit-cluster/C0151
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DepositAcceptsExcessNativeEth(AbstractDetector):
    ARGUMENT = "deposit-accepts-excess-native-eth"
    HELP = "Payable entry point reads msg.value without enforcing an exact-match (`require(msg.value == ...)` / `<=`) and without refunding or forwarding the surplus; overpayment becomes stuck or silently absorbed."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/deposit-accepts-excess-native-eth.yaml"
    WIKI_TITLE = "Payable function accepts and retains excess native ETH"
    WIKI_DESCRIPTION = "A public or external payable function reads msg.value but does not validate it against the expected cost (no `require(msg.value == cost)` or `require(msg.value <= cost)`), does not refund the excess (`refund`, `returnChange`, `.transfer(msg.value - cost)`), and does not forward the full amount onward. Overpayments are silently trapped in the contract balance, becoming either stuck funds or (on bri"
    WIKI_EXPLOIT_SCENARIO = "User calls depositETH() and attaches 1.5 ETH by mistake when the intended fee is 1 ETH. The function credits the user's bookkeeping balance based on a hardcoded amount (or the function-parameter `amount` rather than msg.value), ignoring the 0.5 ETH surplus. The surplus sits in the contract with no withdrawal path and is effectively lost. On L1->L2 bridges this also risks exceeding block-gas/overhe"
    WIKI_RECOMMENDATION = "Either (a) enforce an exact-value invariant with `require(msg.value == expectedCost, ...)`, or (b) accept overpayment but refund the surplus atomically via `(bool ok,) = msg.sender.call{value: msg.value - expectedCost}(\"\"); require(ok);`. Never ignore msg.value. For bridge/messenger functions, add"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\bpayable\\b|msg\\.value'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.value\\s*==|require\\s*\\(\\s*msg\\.value\\s*<=|refund|excess|returnChange|\\.transfer\\s*\\([^)]*msg\\.value|call\\{\\s*value:\\s*msg\\.value\\s*-'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — deposit-accepts-excess-native-eth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
