"""
yul-calldata-loop-no-bounds — generated from reference/patterns.dsl/yul-calldata-loop-no-bounds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py yul-calldata-loop-no-bounds.yaml
Source: defihacklabs/1inch-Fusion-V1-2025-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class YulCalldataLoopNoBounds(AbstractDetector):
    ARGUMENT = "yul-calldata-loop-no-bounds"
    HELP = "Assembly block iterates `calldataload(p)` with `p` growing inside a loop, without asserting `p < calldatasize()`. Attacker-crafted calldata walks past array end, reading uncommitted bytes as protocol input."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/yul-calldata-loop-no-bounds.yaml"
    WIKI_TITLE = "Yul calldata loop without calldatasize bounds"
    WIKI_DESCRIPTION = "Hand-rolled assembly loops over calldata arrays rely on the encoded length prefix to bound iteration. If the loop body reads `calldataload(add(p, 0x20*i))` for `i` growing without comparing `p + 32*i` against `calldatasize()`, the loop can walk past the real end of calldata. Everything beyond calldatasize() returns zero, which is often interpretable as a valid payload (zero amount, zero address), "
    WIKI_EXPLOIT_SCENARIO = "1inch Fusion V1 Settlement 2025-03 ($4.5M): resolver used assembly to iterate over order arrays and call `transferFrom` for each. Attacker encoded the array length as (real-length + 1) and padded the extra entry with attacker-controlled addresses. Yul loop consumed the fake entry; protocol transferred tokens to attacker as if a resolver had submitted a legitimate fill. Fix: `require(offset + 32 * "
    WIKI_RECOMMENDATION = "Every `calldataload` loop in assembly must assert bounds: `if iszero(lt(add(ptr, mul(0x20, i)), calldatasize())) { revert(0,0) }`. Prefer high-level `bytes calldata` decoding with ABI — only drop to Yul when profiled gas gain is measured."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'assembly\\s*\\{'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.assembly_block_matches': 'calldataload\\s*\\('}, {'function.assembly_block_matches': '(for\\s*\\{|add\\s*\\(\\s*\\w+\\s*,\\s*0x20)'}, {'function.assembly_block_not_matches': 'calldatasize\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — yul-calldata-loop-no-bounds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
