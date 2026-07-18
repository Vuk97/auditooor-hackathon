"""
batch-call-gas-bomb-no-gaslimit — generated from reference/patterns.dsl/batch-call-gas-bomb-no-gaslimit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batch-call-gas-bomb-no-gaslimit.yaml
Source: solodit/batch-gas-bomb-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchCallGasBombNoGaslimit(AbstractDetector):
    ARGUMENT = "batch-call-gas-bomb-no-gaslimit"
    HELP = "Batch executor accepts address[] targets (often with caller-supplied calldata) and .call's each target without a per-iteration gas cap. A single malicious target can consume all gas and brick the whole batch — a governance-multicall / AA-bundler denial-of-service vector."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batch-call-gas-bomb-no-gaslimit.yaml"
    WIKI_TITLE = "Batch call gas bomb: unbounded per-iteration gas forwarding"
    WIKI_DESCRIPTION = "The function exposes a batch-call surface — caller supplies an `address[] targets` array (often paired with `bytes[] calldatas`) and the contract iterates, issuing a low-level external call per entry. Solidity forwards all remaining gas to external calls by default; when any single target is attacker-controlled, its fallback / receiver / delegated logic can consume gas indefinitely (explicit loops"
    WIKI_EXPLOIT_SCENARIO = "A governance Timelock exposes `executeBatch(address[] calldata targets, bytes[] calldata data) external` and loops `for (uint i = 0; i < targets.length; i++) targets[i].call(data[i]);`. An attacker includes their own contract as one of the targets with a fallback that runs `while(true) { keccak256(abi.encode(gasleft())); }`. When the Timelock executes the approved batch, the attacker's entry burns"
    WIKI_RECOMMENDATION = "Cap per-entry gas at a small bounded value: `targets[i].call{gas: MAX_CALL_GAS}(data[i])` with `MAX_CALL_GAS` sized to legitimate callees (typically 100k-500k gas). Where entries must be independent, wrap each call in try/catch (for high-level calls) or check `gasleft() > THRESHOLD` before each iter"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_of_type': 'address[]'}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.has_low_level_call': {'op': 'delegatecall'}}, {'function.body_contains_regex': 'for\\s*\\([^)]*\\)\\s*\\{[^}]*\\.(call|delegatecall|transfer|safeTransfer)'}, {'function.body_not_contains_regex': '\\.call\\s*\\{[^}]*gas\\s*:|\\{gas:\\s*\\w|gasLimit\\s*:|MAX_CALL_GAS|BATCH_ENTRY_GAS'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — batch-call-gas-bomb-no-gaslimit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
