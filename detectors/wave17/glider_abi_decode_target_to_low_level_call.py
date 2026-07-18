"""
glider-abi-decode-target-to-low-level-call — generated from reference/patterns.dsl/glider-abi-decode-target-to-low-level-call.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-abi-decode-target-to-low-level-call.yaml
Source: glider-docs/arbitrary-calls-via-abi-decode-seneca-arcadia-moonhacker
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAbiDecodeTargetToLowLevelCall(AbstractDetector):
    ARGUMENT = "glider-abi-decode-target-to-low-level-call"
    HELP = "External function decodes a caller-supplied bytes blob via abi.decode and feeds the decoded address/calldata into a low-level call. Attacker schedules the contract to transferFrom victim approvals into their own wallet. Pattern behind Seneca, Moonhacker, and Arcadia exploits."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-abi-decode-target-to-low-level-call.yaml"
    WIKI_TITLE = "abi.decode feeds arbitrary target + calldata to `.call()` — token drain"
    WIKI_DESCRIPTION = "When a contract exposes an `execute(bytes) external` pattern (router / periphery / bridge executor) and decodes the blob into a target + calldata without a whitelist, the attacker fully controls what the contract calls. Because the contract is the `msg.sender` of the inner call, any ERC-20 approvals the contract holds — or any approvals given *to* the contract by other users — can be redirected by"
    WIKI_EXPLOIT_SCENARIO = "A yield router exposes `executeStrategy(bytes calldata blob) external` which runs `(address target, bytes memory data) = abi.decode(blob, (address, bytes)); target.call(data);`. Alice has approved the router for 1000 USDC (expecting deposit flows). Attacker calls `executeStrategy(abi.encode(USDC, abi.encodeWithSelector(IERC20.transferFrom.selector, alice, attacker, 1000e6)))`. The router — as msg."
    WIKI_RECOMMENDATION = "Never let a user-decoded address become a call target. Maintain a governance-controlled `approvedTargets[address]` whitelist and `require(approvedTargets[target])` before the call. For periphery / aggregator patterns, also sanitize the selector: reject any `transferFrom`, `permit`, `approve`, or pro"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'abi\\.decode\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'bytes'}, {'function.body_contains_regex': 'abi\\.decode\\s*\\('}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '\\.call\\s*(?:\\{[^}]*\\})?\\s*\\(|\\.delegatecall\\s*\\(|\\.staticcall\\s*\\('}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': '(?:\\btarget\\b|\\bto\\b|\\bcallee\\b|\\bexec\\b|\\bcontract_\\b|\\bdest\\b|\\bexecutor\\b|\\brouter\\b|\\btarg\\b)\\s*\\.\\s*(call|delegatecall)\\s*(?:\\{|\\()'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:whitelist|allowed|trusted|approved[CT]|isTrusted|isAllowed)|hasRole|onlyOwner|onlyAdmin'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-abi-decode-target-to-low-level-call: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
