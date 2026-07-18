"""
weth-unwrap-to-non-receiving-contract — generated from reference/patterns.dsl/weth-unwrap-to-non-receiving-contract.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py weth-unwrap-to-non-receiving-contract.yaml
Source: solodit-cluster/cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WethUnwrapToNonReceivingContract(AbstractDetector):
    ARGUMENT = "weth-unwrap-to-non-receiving-contract"
    HELP = "Function unwraps WETH via WETH.withdraw and forwards native ETH to msg.sender without a try/catch, code-length guard, or receiveETH callback; contract senders without payable receive()/fallback revert the whole interaction."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/weth-unwrap-to-non-receiving-contract.yaml"
    WIKI_TITLE = "WETH unwrap-and-forward to msg.sender without contract-receiver guard"
    WIKI_DESCRIPTION = "A public or external function calls WETH.withdraw(amount) to convert WETH back to native ETH and then forwards that ETH to msg.sender using a low-level .call{value:}, .transfer(...), or .send(...). No try/catch, recipient.code.length / Address.isContract check, or dedicated receiveETH(...) hook is present to handle contract senders. Because contract callers that lack a payable receive()/fallback ("
    WIKI_EXPLOIT_SCENARIO = "Protocol P exposes withdrawETH() that burns the caller's LP shares, calls WETH.withdraw(amount) to unwrap the pool's WETH reserves, and then forwards the resulting ETH to msg.sender via payable(msg.sender).transfer(amount). A Safe multisig S holds LP shares and calls withdrawETH(). The unwrap succeeds, the .transfer pushes ETH to S with only a 2300-gas stipend, S's fallback logic exceeds the stipe"
    WIKI_RECOMMENDATION = "Either (a) keep the output as WETH and let the caller unwrap when appropriate for its own receive() semantics, (b) wrap the ETH forward in a try/catch that falls back to re-wrapping and sending WETH on recipient revert, or (c) check recipient.code.length / Address.isContract and route contract recip"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'WETH\\.withdraw\\s*\\(|weth\\.withdraw\\s*\\(|IWETH\\.withdraw\\s*\\(|IWETH9\\.withdraw'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.call\\s*\\{\\s*value|\\.transfer\\s*\\(|\\.send\\s*\\('}, {'function.body_not_contains_regex': 'try\\s+|catch\\s*\\{|recipient\\.code\\.length|Address\\.isContract|receiveETH\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — weth-unwrap-to-non-receiving-contract: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
