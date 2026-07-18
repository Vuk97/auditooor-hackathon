"""
r94-loop-merkle-proof-forgeable — generated from reference/patterns.dsl/r94-loop-merkle-proof-forgeable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-merkle-proof-forgeable.yaml
Source: loop-cycle-30-merkle-proof-forgeable-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopMerkleProofForgeable(AbstractDetector):
    ARGUMENT = "r94-loop-merkle-proof-forgeable"
    HELP = "r94-loop-merkle-proof-forgeable"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-merkle-proof-forgeable.yaml"
    WIKI_TITLE = "r94-loop-merkle-proof-forgeable"
    WIKI_DESCRIPTION = "r94-loop-merkle-proof-forgeable"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-merkle-proof-forgeable"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(MerkleProof|verifyProof|keccak256|sha256)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(verifyProof|verifyMerkle|checkInclusion|proveInclusion|verifyInclusion)'}, {'function.source_matches_regex': 'keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\(|keccak256\\s*\\(\\s*abi\\.encode\\s*\\('}, {'function.not_source_matches_regex': 'LEAF_TAG|NODE_TAG|0x00|0x01|domainSeparator|leafPrefix|nodePrefix|\nabi\\.encodePacked\\s*\\(\\s*bytes1\\s*\\(\\s*0x0|\nabi\\.encode\\s*\\(\\s*uint8\\s*\\(\\s*0\\s*\\),\n'}]

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
                info = [f, f" — r94-loop-merkle-proof-forgeable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
