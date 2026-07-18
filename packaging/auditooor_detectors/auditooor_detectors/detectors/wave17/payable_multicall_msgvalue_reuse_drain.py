"""
payable-multicall-msgvalue-reuse-drain — generated from reference/patterns.dsl/payable-multicall-msgvalue-reuse-drain.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py payable-multicall-msgvalue-reuse-drain.yaml
Source: solodit/multicall-msgvalue-reuse
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PayableMulticallMsgvalueReuseDrain(AbstractDetector):
    ARGUMENT = "payable-multicall-msgvalue-reuse-drain"
    HELP = "Payable `multicall`/`batch` dispatches each sub-call via `delegatecall` inside a loop. Because `msg.value` is preserved across delegatecalls, an attacker paying once can trigger N copies of any native-ETH refund / credit / pull that reads `msg.value`, draining the contract (samczsun's classic)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/payable-multicall-msgvalue-reuse-drain.yaml"
    WIKI_TITLE = "Payable multicall reuses `msg.value` across delegatecalls — refund drain"
    WIKI_DESCRIPTION = "`delegatecall` preserves `msg.value` from the outer transaction in every leg of a multicall loop. If any sub-function reads `msg.value` as an authoritative payment amount (credit, refund, auction bid top-up) the attacker can pay once and replay that credit N times by packing N copies of the same sub-call into the batch. Samczsun's Uniswap v3 refund-drain finding is the canonical instance (`two-rig"
    WIKI_EXPLOIT_SCENARIO = "`Multicall.multicall(bytes[] calldata data)` is payable and loops through `data`, calling each leg via `delegatecall(address(this), data[i])`. Sub-call `buy(...)` internally reads `msg.value` to compute a refund on overpayment, crediting the caller with `msg.value - price`. Attacker builds `data = [buy(cheap1), buy(cheap2), buy(cheap3)]`, attaches `1 ether`, and executes. Each leg sees `msg.value "
    WIKI_RECOMMENDATION = "Either: (a) forbid payable multicall — declare the wrapper `nonpayable` and require users to batch off-chain; (b) assert `msg.value == 0` at the top of `multicall`; or (c) track a transient `leftover` balance across legs so the sum of per-leg credits cannot exceed the single outer `msg.value`. Never"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'multicall|batch|delegatecall'}]
    _MATCH = [{'function.is_payable': True}, {'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(multicall|multi_?call|batch|batchCall|aggregate|tryAggregate|execute)[A-Za-z0-9_]*'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': 'delegatecall|functionDelegateCall'}, {'function.body_contains_regex': 'for\\s*\\(|while\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*msg\\.value\\s*==\\s*0|revert\\s+.*msg\\.value|if\\s*\\(\\s*msg\\.value\\s*!=\\s*0\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — payable-multicall-msgvalue-reuse-drain: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
