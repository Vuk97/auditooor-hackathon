"""
tx-refund-native-eth-unchecked — generated from reference/patterns.dsl/tx-refund-native-eth-unchecked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py tx-refund-native-eth-unchecked.yaml
Source: auditooor/round-29
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TxRefundNativeEthUnchecked(AbstractDetector):
    ARGUMENT = "tx-refund-native-eth-unchecked"
    HELP = "Function issues a native-ETH refund via low-level `.call{value: amt}(\"\")` but discards the returned bool; a reverting or self-destructed recipient silently fails the refund while user bookkeeping is already cleared."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/tx-refund-native-eth-unchecked.yaml"
    WIKI_TITLE = "Unchecked native-ETH refund via low-level .call"
    WIKI_DESCRIPTION = "A public/external function performs `.call{value: amt}(\"\")` to forward or refund native ETH but does not capture or require the returned bool. If the recipient is a contract with a reverting / empty / self-destructed fallback, the transfer reverts internally and the call returns `false`, but execution continues. The user's pending balance or pending-refund entry has already been cleared, produci"
    WIKI_EXPLOIT_SCENARIO = "A user deposits 2 ETH and later calls `withdraw()`. The contract zeroes `pending[msg.sender]` and then issues `msg.sender.call{value: 2 ether}(\"\")` without checking the return. The user's smart-account fallback reverts (or the account was self-destructed post-deposit). The inner call fails, bool is discarded, `pending[msg.sender]` is already zero, and the 2 ETH remain stuck in the contract with "
    WIKI_RECOMMENDATION = "Always capture and check the low-level call return: `(bool ok,) = recipient.call{value: amt}(\"\"); require(ok, \"refund failed\");`. Prefer a pull-payment pattern (Address.sendValue + withdrawable credit) so a failing recipient does not corrupt the sender's state. Never discard the boolean from a ."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*value\\s*:\\s*\\w[\\w\\.]*\\s*\\}\\s*\\(\\s*""'}, {'function.body_not_contains_regex': '\\(\\s*bool\\s+(success|ok|sent|refunded|refundOk)\\b|require\\s*\\(\\s*(success|ok|sent|refunded|refundOk)\\b|require\\s*\\([^;]*\\.call\\s*\\{'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — tx-refund-native-eth-unchecked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
