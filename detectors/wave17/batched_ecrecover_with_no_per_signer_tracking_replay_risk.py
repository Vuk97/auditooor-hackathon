"""
batched-ecrecover-with-no-per-signer-tracking-replay-risk - generated from reference/patterns.dsl/batched-ecrecover-with-no-per-signer-tracking-replay-risk.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batched-ecrecover-with-no-per-signer-tracking-replay-risk.yaml
Source: hexens-glider/batch-signature-reuse-exploits
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchedEcrecoverWithNoPerSignerTrackingReplayRisk(AbstractDetector):
    ARGUMENT = "batched-ecrecover-with-no-per-signer-tracking-replay-risk"
    HELP = "Batched signature verification loops over ecrecover results without nonce, used-signature, or signer dedup tracking."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batched-ecrecover-with-no-per-signer-tracking-replay-risk.yaml"
    WIKI_TITLE = "Batched ecrecover lacks per-signer replay tracking"
    WIKI_DESCRIPTION = "A public or external batch signature verifier loops over a signature array and accepts recovered signers, but the function body does not reference nonce, used-signature, seen-signer, bitmap, or monotonic signer-order tracking. The same authorization can be replayed across calls or duplicated inside the batch."
    WIKI_EXPLOIT_SCENARIO = "A multisig-style entry point accepts a digest and `bytes[] signatures`, loops through `ecrecover`, counts valid signers, and executes once the threshold is reached. Because the digest or recovered signer is never marked used and no nonce is consumed, an attacker can submit the same signed payload again."
    WIKI_RECOMMENDATION = "Bind signatures to a consumed nonce or operation id, mark digest/signer pairs as used before executing effects, and reject duplicate signers in each batch with a mapping, bitmap, or strict sorted-signer check."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ecrecover\\s*\\(|\\.recover\\s*\\(|bytes\\s*\\[\\]|bytes32\\s*\\[\\]|Signature\\s*\\[\\]'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\b(for|while)\\s*\\('}, {'function.body_contains_regex': 'ecrecover\\s*\\(|\\.recover\\s*\\('}, {'function.body_contains_regex': 'bytes\\s*\\[\\]\\s*(calldata|memory)?\\s+[A-Za-z_][A-Za-z0-9_]*|bytes32\\s*\\[\\]\\s*(calldata|memory)?\\s+[A-Za-z_][A-Za-z0-9_]*|Signature\\s*\\[\\]\\s*(calldata|memory)?\\s+[A-Za-z_][A-Za-z0-9_]*'}, {'function.body_not_contains_regex': '\\b(nonce|nonces|used|seen|consumed|executed|bitmap|lastSigner|previousSigner|sorted|dedup)\\b'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - batched-ecrecover-with-no-per-signer-tracking-replay-risk: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
