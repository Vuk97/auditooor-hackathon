"""
r74-abi-writeoutputs-memory-corruption — generated from reference/patterns.dsl/r74-abi-writeoutputs-memory-corruption.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-abi-writeoutputs-memory-corruption.yaml
Source: r74b-cross-firm-cs+tob
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74AbiWriteoutputsMemoryCorruption(AbstractDetector):
    ARGUMENT = "r74-abi-writeoutputs-memory-corruption"
    HELP = "Inline-assembly memory write uses a user-influenced index without bounding it against the container; crafted inputs corrupt adjacent memory (scratch, free pointer, or state)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-abi-writeoutputs-memory-corruption.yaml"
    WIKI_TITLE = "Unbounded assembly memory write corrupts non-container memory"
    WIKI_DESCRIPTION = "A function performs an indexed mstore / returndatacopy / calldatacopy where the destination offset is derived from caller-controlled data (a command index, a struct field, a calldata slice). When no require compares the derived index against the container's declared length, attacker-crafted input reaches mstore with an offset outside the container — overwriting the free-memory pointer, scratch spa"
    WIKI_EXPLOIT_SCENARIO = "A 'weiroll'-style command engine decodes a byte to an index and writes the command's return value into state[idx]. The assembly does `mstore(add(statePtr, mul(idx, 0x20)), returnValue)` without checking idx < state.length. Attacker sends idx = 1024 in a command; mstore writes 32 bytes at statePtr + 32768, clobbering the contract's nonce storage slot in memory. A subsequent read of the corrupted sl"
    WIKI_RECOMMENDATION = "Before any mstore / returndatacopy inside a user-reachable function, require the destination offset is within the declared container: `require(idx < state.length, 'oob');`. For returndatacopy, additionally require the source length is within returndatasize(). Prefer high-level Solidity array indexin"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\b(outputs?|states?|commands?|results?|returndata)\\b'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.has_param_name_matching': '(?i)\\b(idx|index|pos|offset|slot|command|commands|state|states|output|outputs)\\b'}, {'function.body_contains_regex': 'assembly\\s*\\{|assembly\\s*\\('}, {'function.assembly_block_matches': '(?i)(mstore\\s*\\(\\s*add\\s*\\(|returndatacopy\\s*\\(|calldatacopy\\s*\\(|codecopy\\s*\\()'}, {'function.body_contains_regex': '(?i)\\b(idx|index|pos|offset)\\b'}, {'function.body_not_contains_regex': '(?i)(require|assert)\\s*\\([^;]*(idx|index|pos|offset)\\s*(<|<=)\\s*\\w+\\.length|(require|assert)\\s*\\([^;]*\\w+\\.length\\s*(>|>=)\\s*(idx|index|pos|offset)|if\\s*\\([^)]*(idx|index|pos|offset)\\s*>=\\s*\\w+\\.length[^)]*\\)\\s*(revert|{[^}]*revert)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-abi-writeoutputs-memory-corruption: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
