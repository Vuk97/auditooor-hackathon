"""
r94-loop-kzg-weak-fiat-shamir-challenge — generated from reference/patterns.dsl/r94-loop-kzg-weak-fiat-shamir-challenge.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-kzg-weak-fiat-shamir-challenge.yaml
Source: solodit-64105-sherlock-fusaka-upgrade
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopKzgWeakFiatShamirChallenge(AbstractDetector):
    ARGUMENT = "r94-loop-kzg-weak-fiat-shamir-challenge"
    HELP = "r94-loop-kzg-weak-fiat-shamir-challenge"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-kzg-weak-fiat-shamir-challenge.yaml"
    WIKI_TITLE = "r94-loop-kzg-weak-fiat-shamir-challenge"
    WIKI_DESCRIPTION = "r94-loop-kzg-weak-fiat-shamir-challenge"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-kzg-weak-fiat-shamir-challenge"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(KZG|FiatShamir|Transcript|BatchVerify|cKzg|Kzg4844|BlobVerifier)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(verifyCellKzgProofBatch|verifyKzgBatch|computeChallenge|deriveChallenge|fiatShamir|computeRPowers|verifyKzgProofBatch)'}, {'function.source_matches_regex': '(hashToField|hashToBlsField|transcript\\.(append|absorb|update)|keccak256\\s*\\(|sha256\\s*\\(|poseidon\\s*\\()'}, {'function.not_source_matches_regex': '(cellIndices|cell_indices|cellCount|num_?cells|rowIndices|columnIndices|domainSep|DST|FIAT_SHAMIR_PROTOCOL|commitments\\.length)'}]

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
                info = [f, f" — r94-loop-kzg-weak-fiat-shamir-challenge: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
