"""
merkle-proof-index-collision — generated from reference/patterns.dsl/merkle-proof-index-collision.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py merkle-proof-index-collision.yaml
Source: solodit/airdrop-merkle-replay
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MerkleProofIndexCollision(AbstractDetector):
    ARGUMENT = "merkle-proof-index-collision"
    HELP = "Claim function verifies a merkle proof against a stored root but never marks the leaf/index as claimed. The same proof can be replayed until the distribution is drained."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/merkle-proof-index-collision.yaml"
    WIKI_TITLE = "Merkle claim replay: no per-leaf claimed[] flag"
    WIKI_DESCRIPTION = "The contract stores a merkleRoot and lets users claim by submitting a bytes32[] proof. The function calls MerkleProof.verify (or an inline verify) to authenticate the leaf, but never records that the leaf has been consumed — no `claimed[leafHash] = true`, no per-index flag, no nullifier set. A caller can submit the same proof repeatedly and receive the airdrop multiple times."
    WIKI_EXPLOIT_SCENARIO = "Alice's leaf encodes (msg.sender, amount). She calls claim(proof, amount) and receives her allocation. She calls claim(proof, amount) again — the proof still verifies, the contract still transfers, because no claimed-flag was set. She drains the whole distribution."
    WIKI_RECOMMENDATION = "Add a `mapping(bytes32 => bool) claimed` (or per-index bitmap). Compute the leaf hash once, `require(!claimed[leaf])`, then set `claimed[leaf] = true` BEFORE making the transfer. OpenZeppelin's MerkleDistributor and Uniswap's MerkleDistributor are reference implementations."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'merkleRoot|root|claimed|airdrop'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claim|claimAirdrop|_claim|claimReward|redeemClaim)$'}, {'function.body_contains_regex': {'regex': 'MerkleProof\\.|\\.verify\\s*\\(\\s*proof|keccak256\\s*\\(\\s*abi\\.encode(Packed)?\\s*\\(\\s*msg\\.sender'}}, {'function.body_not_contains_regex': 'claimed\\[|hasClaimed|_claimed\\[|require\\s*\\(\\s*!claimed|claimed\\[.*\\]\\s*=\\s*true'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — merkle-proof-index-collision: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
