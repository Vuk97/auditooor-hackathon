"""
iavl-merkle-proof-absence-accepted-as-existence — generated from reference/patterns.dsl/iavl-merkle-proof-absence-accepted-as-existence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py iavl-merkle-proof-absence-accepted-as-existence.yaml
Source: auditooor-R76-rekt-bnb-bridge-2022
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IavlMerkleProofAbsenceAcceptedAsExistence(AbstractDetector):
    ARGUMENT = "iavl-merkle-proof-absence-accepted-as-existence"
    HELP = "Bridge proof verifier does not distinguish between existence and absence proofs, nor reject empty proof-op lists. An attacker submits a degenerate 'absence' proof that the code paths accept as existence."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/iavl-merkle-proof-absence-accepted-as-existence.yaml"
    WIKI_TITLE = "IAVL/Merkle bridge verifier accepts empty/absence proof as existence proof"
    WIKI_DESCRIPTION = "IAVL (Cosmos), Merkle-patricia (Ethereum) and similar proof systems support multiple proof modes: existence proofs, absence proofs, and range proofs. A verifier that returns a single boolean without distinguishing these modes can be tricked when the caller supplies an absence/empty proof that satisfies the boolean check but corresponds to a leaf the caller constructs. If the bridge then uses the c"
    WIKI_EXPLOIT_SCENARIO = "Attacker studies the IAVL proof library used by BNB Bridge. Identifies that `verifyProof(proof, key, value, rootHash)` returns true when `proof.ops.length == 0` because the outer loop short-circuits. Crafts a proof with zero inner operations but a claimed leaf `{token: BNB, amount: 2_000_000e18, to: attacker}`. Submits to `BSCTokenHub.handlePayload(proof, header, payload)`. Header verify passes (l"
    WIKI_RECOMMENDATION = "Require explicit proof-type verification: `require(proof.type == ProofType.EXISTENCE, 'not existence');`. Reject proofs with zero hashing operations: `require(proof.ops.length > 0);`. Compute the claimed leaf's hash from the provided `(key, value)` and require it matches an inner-node output of the "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Bridge / cross-chain verifier calls an IAVL or similar variadic-proof library and uses the boolean return to gate message execution.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)verifyProof|verifyMerkleProof|verifyIAVL|verifyRangeProof|handlePayload|handleMessage|deliverPackage'}, {'function.body_contains_regex': '(?i)IAVLMerkleProof|IAVLVerif|verifyMembership|rangeProof|proof\\.verify|merkleVerifier'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*proof\\.ops\\.length\\s*>\\s*0|require\\s*\\(\\s*proof\\.leaves\\.length\\s*>=?\\s*1|require\\s*\\(\\s*!proof\\.isAbsenceProof|requireExistenceProof|proofType\\s*==\\s*EXISTENCE'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — iavl-merkle-proof-absence-accepted-as-existence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
