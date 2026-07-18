"""
glider-inverted-signature-merkle-proof-check — generated from reference/patterns.dsl/glider-inverted-signature-merkle-proof-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-inverted-signature-merkle-proof-check.yaml
Source: glider-query-db/inverted-signaturemerkle-proofsaccess-control-veri
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderInvertedSignatureMerkleProofCheck(AbstractDetector):
    ARGUMENT = "glider-inverted-signature-merkle-proof-check"
    HELP = "Access-control check uses inverted boolean: `require(!verify(...))` permits only invalid signatures/proofs. Anyone who supplies garbage passes; legitimate proof-holders are rejected."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-inverted-signature-merkle-proof-check.yaml"
    WIKI_TITLE = "Inverted Merkle-proof or signature check"
    WIKI_DESCRIPTION = "A `require(!MerkleProof.verify(...))` or `require(!ECDSA.recover(...) == user)` check logically negates the intended gate. Inverted guards allow adversaries to pass with random input while rejecting honest users."
    WIKI_EXPLOIT_SCENARIO = "A claim function: `require(!MerkleProof.verify(proof, root, leaf), 'not in list')`. Attacker passes random proof bytes that do NOT verify — condition is true — claim succeeds."
    WIKI_RECOMMENDATION = "Remove the negation. Usually `require(MerkleProof.verify(...), 'not in list')` is intended."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.has_high_level_call_named': 'recover|ecrecover'}, {'function.body_contains_regex': 'require\\s*\\(\\s*!\\s*(MerkleProof\\.(verify|verifyCalldata)|ECDSA\\.recover|_verifyProof|_verify|isValidSignature)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-inverted-signature-merkle-proof-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
