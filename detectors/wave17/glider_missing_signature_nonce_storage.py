"""
glider-missing-signature-nonce-storage — generated from reference/patterns.dsl/glider-missing-signature-nonce-storage.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-missing-signature-nonce-storage.yaml
Source: glider-query-db/missing-signature-nonce-storage
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderMissingSignatureNonceStorage(AbstractDetector):
    ARGUMENT = "glider-missing-signature-nonce-storage"
    HELP = "Signature verification path does not reference a nonce, deadline, or consumed-sig mapping. Signed messages are replayable indefinitely."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-missing-signature-nonce-storage.yaml"
    WIKI_TITLE = "Signed-message replay: no nonce and no deadline"
    WIKI_DESCRIPTION = "Any ECDSA-verified payload that does not bind to a stateful nonce (per-signer counter) or a strict deadline can be replayed arbitrarily. Combine nonce + deadline for safety."
    WIKI_EXPLOIT_SCENARIO = "User signs authorization for a single withdrawal. The contract verifies signature but stores no state. Attacker replays the signature, draining repeatedly until balance depleted."
    WIKI_RECOMMENDATION = "Include `nonces[signer]` or `usedSignatures[hash]` in the signed payload and mark consumed on use."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover|ECDSA\\.recover|isValidSignature'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'ecrecover\\s*\\(|ECDSA\\.recover\\s*\\('}, {'function.body_not_contains_regex': 'nonce|_useNonce|_useCheckedNonce|usedSignatures|usedHashes|consumedSig'}, {'function.body_not_contains_regex': 'deadline|expiry|expiresAt|validUntil'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-missing-signature-nonce-storage: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
