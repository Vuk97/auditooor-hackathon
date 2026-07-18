"""
inverted-signature-merkle-proofs-access-control-verification-passes-wh — generated from reference/patterns.dsl/inverted-signature-merkle-proofs-access-control-verification-passes-wh.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py inverted-signature-merkle-proofs-access-control-verification-passes-wh.yaml
Source: Hexens Glider query: inverted-signaturemerkle-proofsaccess-control-veri
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InvertedSignatureMerkleProofsAccessControlVerificationPassesWh(AbstractDetector):
    ARGUMENT = "inverted-signature-merkle-proofs-access-control-verification-passes-wh"
    HELP = "Access-control verification is negated, so invalid proofs or signatures satisfy the guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/inverted-signature-merkle-proofs-access-control-verification-passes-wh.yaml"
    WIKI_TITLE = "Inverted signature / merkle-proof access-control verification"
    WIKI_DESCRIPTION = "A public or external access-control path negates a verification helper inside `require` or `assert`, for example `require(!_verifyWhitelist(...))` or `require(!MerkleProof.verify(...))`. That flips the intended gate and lets invalid proofs or signatures pass while valid ones fail."
    WIKI_EXPLOIT_SCENARIO = "A claim function is supposed to admit only addresses with a valid merkle proof. Because the code uses `require(!_verifyWhitelist(proof, leaf))`, an attacker can present garbage proof data, satisfy the negated check, and still mark the claim as successful."
    WIKI_RECOMMENDATION = "Remove the negation and keep the positive verification condition. This row remains NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(signature|merkle|proof|whitelist|allowlist|role|auth|access)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?si)\\b(require|assert)\\s*\\(\\s*!\\s*(?:\\(\\s*)?(?:MerkleProof\\.(?:verify|verifyCalldata)|_?verify[A-Za-z0-9_]*|isValidSignature(?:Now)?|hasRole)\\s*\\('}, {'function.body_contains_regex': '(?i)(signature|merkle|proof|whitelist|allowlist|role|auth|access)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture|harness)\\b'}]

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
                info = [f, f" — inverted-signature-merkle-proofs-access-control-verification-passes-wh: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
