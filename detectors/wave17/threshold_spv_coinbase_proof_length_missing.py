"""
threshold-spv-coinbase-proof-length-missing — generated from reference/patterns.dsl/threshold-spv-coinbase-proof-length-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py threshold-spv-coinbase-proof-length-missing.yaml
Source: auditooor-R76-immunefi-threshold-network
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ThresholdSpvCoinbaseProofLengthMissing(AbstractDetector):
    ARGUMENT = "threshold-spv-coinbase-proof-length-missing"
    HELP = "Bitcoin SPV verifier does not require coinbase proof length to match the target-tx proof length. Enables 64-byte-tx merkle malleability: attacker claims a fake tx at one level deeper."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/threshold-spv-coinbase-proof-length-missing.yaml"
    WIKI_TITLE = "BTC SPV verifier skips coinbase-proof-length equality — 64-byte tx malleability"
    WIKI_DESCRIPTION = "Bitcoin's merkle tree hashes 32-byte nodes. A 64-byte transaction is ambiguous — its bytes can also be interpreted as two concatenated merkle nodes one level up. SPV verifiers must establish the tx's tree depth by comparing against the coinbase's proof length (coinbase is always at a known depth). Without this equality check, an attacker crafts a 64-byte coinbase and a forged 32-byte target tx mat"
    WIKI_EXPLOIT_SCENARIO = "Threshold's ValidateSPV.prove accepted proofs without requiring `coinbaseProof.length == txProof.length`. An attacker's 64-byte coinbase provided both interpretations; a forged 32-byte tx-id matching the second half was accepted as included, minting tBTC without depositing BTC."
    WIKI_RECOMMENDATION = "Enforce `coinbaseProof.length == txProof.length` in every SPV verifier. Additionally require `txBytes.length != 64` (reject 64-byte txs outright — BIP-141 post-segwit txs should never be exactly 64 bytes). Add validation that both proofs resolve to the same merkle root at the same height."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'chain.is_btc_spv_verifier': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^prove$|verifyProof|validateSPV|verifyMerkle'}, {'function.body_contains_regex': '(?i)txProof\\s*\\.\\s*length|intermediateNodes\\.length|merkleProof\\.length'}, {'function.body_not_contains_regex': '(?i)coinbaseProof\\.length\\s*==\\s*txProof\\.length|coinbase_proof_len\\s*==|require\\s*\\(\\s*\\w+\\.length\\s*==\\s*\\w+\\.length'}, {'function.body_contains_regex': '(?i)coinbase|coinbaseTx|coinbase_tx'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — threshold-spv-coinbase-proof-length-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
