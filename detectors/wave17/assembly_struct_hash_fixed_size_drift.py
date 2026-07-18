"""
assembly-struct-hash-fixed-size-drift — generated from reference/patterns.dsl/assembly-struct-hash-fixed-size-drift.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py assembly-struct-hash-fixed-size-drift.yaml
Source: polymarket-v2-meta-class-r41
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AssemblyStructHashFixedSizeDrift(AbstractDetector):
    ARGUMENT = "assembly-struct-hash-fixed-size-drift"
    HELP = "EIP-712 struct hash computed via hand-rolled assembly with a hardcoded byte length — silent mismatch if struct fields change."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/assembly-struct-hash-fixed-size-drift.yaml"
    WIKI_TITLE = "Assembly EIP-712 hash with hardcoded length drifts on struct change"
    WIKI_DESCRIPTION = "Inline-assembly struct-hash computations of the form keccak256(sub(order, 0x20), 0x180) bake the struct size into a magic number. If a field is added to the struct (or the typehash) without updating the byte length, the digest silently diverges from abi.encode(order) — signatures become invalid (DoS) or, worse, collide across struct variants."
    WIKI_EXPLOIT_SCENARIO = "Protocol upgrades Order to include a new field. Off-chain signer uses abi.encode for the new field count; on-chain hash still reads the old length. Every new order fails validation (DoS), or — in a partial-migration scenario — a pre-upgrade signature over the old struct matches the new digest, enabling cross-version replay."
    WIKI_RECOMMENDATION = "Use abi.encode(TYPEHASH, order.field1, ..., order.fieldN) and let the Solidity compiler derive the length. If assembly is required for gas, assert the length via assert(memoryPointer == expected) and update both the typehash and the length in a single change."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.assembly_block_matches': 'keccak256\\('}, {'function.assembly_block_matches': '0x[0-9a-fA-F]+'}, {'function.body_contains_regex': 'ORDER_TYPEHASH|STRUCT_TYPEHASH|_TYPEHASH'}, {'function.assembly_block_not_matches': 'mload\\(.*\\).*mul\\(0x20'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — assembly-struct-hash-fixed-size-drift: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
