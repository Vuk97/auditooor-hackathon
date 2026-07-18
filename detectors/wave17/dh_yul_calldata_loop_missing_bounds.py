"""
dh-yul-calldata-loop-missing-bounds — generated from reference/patterns.dsl/dh-yul-calldata-loop-missing-bounds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-yul-calldata-loop-missing-bounds.yaml
Source: defihacklabs/1inch-Fusion-V1-2025-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhYulCalldataLoopMissingBounds(AbstractDetector):
    ARGUMENT = "dh-yul-calldata-loop-missing-bounds"
    HELP = "Yul loop uses `calldataload` with loop-induced pointer but never asserts against `calldatasize()` — out-of-bounds read."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-yul-calldata-loop-missing-bounds.yaml"
    WIKI_TITLE = "Yul calldata loop missing calldatasize bound"
    WIKI_DESCRIPTION = "Hand-written assembly that walks a calldata array must verify each read address is less than `calldatasize()`. Without that bound, attacker-crafted calldata can cause the loop to dereference memory beyond the array, treating dirty bytes as valid entries and bypassing intended validation."
    WIKI_EXPLOIT_SCENARIO = "1inch Fusion V1 Settlement 2025-03 $4.5M: the resolver iterated an order-list in Yul, computing offsets via `mul(i, 32)` added to a base pointer. Attacker submitted calldata with truncated length prefix; the loop body read past array end, interpreting attacker-chosen trailing bytes as legitimate order entries, authorising unintended transfers."
    WIKI_RECOMMENDATION = "In every Yul loop over calldata, add `if iszero(lt(ptr, calldatasize())) { revert(0,0) }` before the load. Or prefer Solidity's high-level `for` which inserts bounds automatically. For trust-critical parsers, unit-test with fuzz calldata."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'assembly|yul'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.assembly_block_matches': 'calldataload\\s*\\('}, {'function.assembly_block_matches': 'for\\s*\\{'}, {'function.assembly_block_not_matches': 'calldatasize\\s*\\(\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-yul-calldata-loop-missing-bounds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
