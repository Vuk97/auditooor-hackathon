"""
can-merkle-drop-no-per-index-flag — generated from reference/patterns.dsl/can-merkle-drop-no-per-index-flag.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-merkle-drop-no-per-index-flag.yaml
Source: cantina/2024-2025-merkle-claim-replay-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanMerkleDropNoPerIndexFlag(AbstractDetector):
    ARGUMENT = "can-merkle-drop-no-per-index-flag"
    HELP = "Merkle-drop claim() verifies proof + transfers tokens but never marks the index/leaf as consumed — same proof can be replayed until the pool is drained."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-merkle-drop-no-per-index-flag.yaml"
    WIKI_TITLE = "Merkle claim does not mark index/leaf as claimed"
    WIKI_DESCRIPTION = "Merkle-drop contracts must bind a successful proof verification to a per-index (or per-leaf-hash) sold flag, otherwise the same proof can be resubmitted in every subsequent block. The proof is public (broadcast in the first tx), and without a claimed[index] write the contract has no memory of prior claims. Distinct from Merkle-root rotation bugs and from leaf-encoding collisions — this is the simp"
    WIKI_EXPLOIT_SCENARIO = "Cantina competition class (multiple 2024-2025 contests): airdrop contract `claim(index, account, amount, proof)` verifies the proof and calls `token.safeTransfer(account, amount)`. No write to `claimed[index]`. First claimant resubmits the identical call in a loop from a bot, draining the airdrop pool. Variant: contract tracks `totalClaimedBy[user]` but never compares it to the user's maxEntitleme"
    WIKI_RECOMMENDATION = "Always set and check a claimed flag: `require(!claimed[index], \"claimed\"); claimed[index] = true;` before the transfer. For dense indices, use OpenZeppelin `BitMaps` to save gas. Alternatively, bind the claim to a nonce in the leaf and mark `usedNonces[leafHash] = true`. Add a unit test that attem"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'MerkleProof|merkleRoot|merkleRoot\\s*='}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(claim|claimReward|claimDrop|claimAirdrop|redeemClaim)'}, {'function.body_contains_regex': 'MerkleProof\\.(verify|verifyCalldata)|_verify\\s*\\('}, {'function.body_contains_regex': '(safeTransfer|transfer\\s*\\(|_mint\\s*\\()'}, {'function.body_not_contains_regex': 'claimed\\s*\\[|isClaimed\\s*\\(|BitMaps\\.|_setClaimed|setClaimed|alreadyClaimed|claims\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-merkle-drop-no-per-index-flag: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
