"""
imm-spv-merkle-coinbase-proof-length-mismatch — generated from reference/patterns.dsl/imm-spv-merkle-coinbase-proof-length-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py imm-spv-merkle-coinbase-proof-length-mismatch.yaml
Source: immunefi/threshold-transaction-malleability
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ImmSpvMerkleCoinbaseProofLengthMismatch(AbstractDetector):
    ARGUMENT = "imm-spv-merkle-coinbase-proof-length-mismatch"
    HELP = "SPV `prove()` checks Bitcoin-style merkle inclusion but does not reject 64-byte transactions nor compare proof length against the coinbase proof. A malicious 64-byte tx can be interpreted as an internal merkle node, faking inclusion."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/imm-spv-merkle-coinbase-proof-length-mismatch.yaml"
    WIKI_TITLE = "SPV proof misses coinbase length / 64-byte tx disambiguation (Threshold tBTC)"
    WIKI_DESCRIPTION = "Bitcoin merkle trees hash leaves with `sha256(sha256(txBytes))` and internal nodes with `sha256(sha256(left || right))`, where left/right are 32-byte hashes — so internal node preimages are always 64 bytes. A Bitcoin transaction can also legally be 64 bytes long. An attacker can construct a 64-byte \"transaction\" whose bytes, when interpreted as `left || right`, collide with the hash of an intern"
    WIKI_EXPLOIT_SCENARIO = "Threshold tBTC (Aug 2023): the `prove()` function called `verifyHash256Merkle(txHash, proof, index, root)`. An attacker (who can influence coinbase data of a block they mine, or exploits a historical block) inserts a 64-byte payload that doubles as an internal merkle node. `prove()` returns true for a tx that was never in the block. The tBTC minter then credits the attacker with BTC that does not "
    WIKI_RECOMMENDATION = "Two independent guards, both required: (a) reject any transaction preimage whose length is exactly 64 bytes (`require(txBytes.length != 64)`), and (b) always verify the coinbase transaction's inclusion proof and require `merkleProof.length == coinbaseProof.length`. Prefer audited libraries (Summa `V"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'verifyHash256Merkle|ValidateSPV|merkleRoot|merkleProof|\\bSPV\\b'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '^(prove|_prove|verifyProof|validateProof|verifyInclusion|verifySPV)$'}, {'function.body_contains_regex': 'verifyHash256Merkle|_verifyMerkle|merkleProof|merkleRoot'}, {'function.body_not_contains_regex': 'coinbaseProof|coinbaseTxLength|proofLength\\s*==\\s*coinbaseProofLength|require\\s*\\(\\s*txBytes\\.length\\s*!=\\s*64|rejectCoinbaseCollision'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — imm-spv-merkle-coinbase-proof-length-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
