"""
merkle-proof-no-leaf-bottom-hash-distinguisher — generated from reference/patterns.dsl/merkle-proof-no-leaf-bottom-hash-distinguisher.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-proof-no-leaf-bottom-hash-distinguisher.yaml
Source: lisa-mine-r99-case-09044-spearbit-opensea-seaport-2022-05
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleProofNoLeafBottomHashDistinguisher(AbstractDetector):
    ARGUMENT = "merkle-proof-no-leaf-bottom-hash-distinguisher"
    HELP = "A Merkle-proof verifier accepts a candidate leaf, walks the proof, and asserts `computedRoot == storedRoot` — but never tags the leaf hash differently from the intermediate-node hash. Standard binary Merkle constructions (RFC 6962, Lighthouse, OpenZeppelin) require leaves to be hashed under a domain"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-proof-no-leaf-bottom-hash-distinguisher.yaml"
    WIKI_TITLE = "Merkle proof verifier does not domain-separate leaf hashes from intermediate hashes"
    WIKI_DESCRIPTION = "Pattern fires on `verifyProof`-style functions that compute a candidate `computedHash = keccak256(...)` chain rolled up against `storedRoot`, with no domain-separator byte (`0x00` for leaf, `0x01` for intermediate) and no per-leaf re-hashing under a tag. Any internal node of a published Merkle tree is a valid leaf-space pre-image; submitting `internalHash` as `tokenId` and the rest of the tree-tra"
    WIKI_EXPLOIT_SCENARIO = "OpenSea Seaport accepts an order specifying a Merkle root over a set of `tokenId`s the offerer is willing to receive. The fulfiller submits `tokenId = intermediateHash`, `proof = [siblingsTowardRoot]` and `verifyProof` returns true — `intermediateHash` was never minted as a real NFT, but the verifier cannot tell that. Funds release on the seller's signature; the buyer 'delivers' a non-existent tok"
    WIKI_RECOMMENDATION = "Domain-separate the leaf hash: `bytes32 leaf = keccak256(abi.encode(uint8(0x00), candidate));` and the intermediate hash: `keccak256(abi.encode(uint8(0x01), left, right));`. Or adopt OpenZeppelin's `MerkleProof.verifyCalldata` which already standardises on `keccak256(bytes.concat(...))` and rejects "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'MerkleProof|verifyProof|merkleRoot|root\\s*=|criteriaRoot|identifierOrCriteria'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'verifyProof|verify|isValidProof|isValid|_verify|verifyMerkle|verifyCriteria'}, {'function.body_contains_regex': '\\bcomputedHash\\s*=\\s*keccak256|hash\\s*=\\s*keccak256\\s*\\(\\s*abi\\.encodePacked\\s*\\([^)]*\\bcomputedHash'}, {'function.body_contains_regex': '==\\s*[A-Za-z_]*[Rr]oot|return\\s+[A-Za-z_]+\\s*==\\s*[A-Za-z_]*[Rr]oot'}, {'function.body_not_contains_regex': 'uint8\\s*\\(\\s*0x?0+\\s*\\)|hex\\s*"00"|hex\\s*"0x00"|leafTag|MerkleProof\\.verify|MerkleProofUpgradeable\\.verify'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — merkle-proof-no-leaf-bottom-hash-distinguisher: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
