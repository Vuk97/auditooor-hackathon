"""
balancer-merkle-orchard-batched-duplicate-claim — generated from reference/patterns.dsl/balancer-merkle-orchard-batched-duplicate-claim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py balancer-merkle-orchard-batched-duplicate-claim.yaml
Source: auditooor-R76-immunefi-balancer-merkle-orchard-50ETH
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BalancerMerkleOrchardBatchedDuplicateClaim(AbstractDetector):
    ARGUMENT = "balancer-merkle-orchard-batched-duplicate-claim"
    HELP = "Batched Merkle claim processor defers bitmap update until the (channel, word) tuple changes. Duplicate claims in the array share the tuple and never mark the bit — same leaf claimed N times."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/balancer-merkle-orchard-batched-duplicate-claim.yaml"
    WIKI_TITLE = "Batched Merkle claim processor skips dedup when consecutive entries share channel/word"
    WIKI_DESCRIPTION = "MerkleOrchard-style batch claim functions process a sorted array of claims, accumulating amounts per (channel, wordIndex) tuple and flushing the bitmap write only when the tuple changes. If an attacker submits the SAME claim repeatedly in the array (same channel, same wordIndex, same leaf), the tuple-change condition is never triggered between entries, the bitmap write is skipped, and the accumula"
    WIKI_EXPLOIT_SCENARIO = "Balancer Merkle Orchard's `claimDistributions` processed [claimX, claimX, claimX, ...]. Each iteration hit `currentChannelId == distributionChannelId` and skipped `_setClaimedBits`. Total sent = N × claimX.amount. A single tx drained $3.2M across mainnet/polygon/arbitrum. Fix: per-iteration `require(!isClaimed(word, bit))` OR mark bit immediately."
    WIKI_RECOMMENDATION = "Mark each claim as consumed INSIDE the per-iteration body, not in a batched tail flush. Add explicit `require(!_isClaimed(channelId, wordIndex, bit))` before accumulating. Invariant test: `forall claim sequence with any duplicates, total paid out == sum(unique amounts)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)claimDistributions|claimWithCallback|_processClaims|batchClaim'}, {'function.body_contains_regex': '(?i)for\\s*\\(\\s*uint\\s+\\w+\\s*=\\s*0.*claims\\.length|claims\\[i\\]\\.distributionId'}, {'function.body_contains_regex': '(?i)currentChannelId\\s*==|currentWordIndex\\s*==|lastChannelId\\s*==|sameChannel'}, {'function.body_not_contains_regex': '(?i)_setClaimedBits\\s*\\(\\s*currentChannelId.*currentClaim|require\\s*\\(\\s*!isClaimed\\s*\\(|require\\s*\\(\\s*claims\\[i\\]\\.distributionId\\s*!=\\s*claims\\[i-1\\]\\.distributionId'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — balancer-merkle-orchard-batched-duplicate-claim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
