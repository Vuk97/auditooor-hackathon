"""
cached-bucket-writeback-without-empty-array-guard — generated from reference/patterns.dsl/cached-bucket-writeback-without-empty-array-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cached-bucket-writeback-without-empty-array-guard.yaml
Source: auditooor-R75-nethermind-royco-vaults-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CachedBucketWritebackWithoutEmptyArrayGuard(AbstractDetector):
    ARGUMENT = "cached-bucket-writeback-without-empty-array-guard"
    HELP = "A helper caches a per-user claim bitmap in a local variable initialized to zero, then loops over user-supplied ids to update the cache, and unconditionally writes the cache back to storage at the end. If the loop runs zero times (empty array), the zero-initialized cache is written back, clearing all"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cached-bucket-writeback-without-empty-array-guard.yaml"
    WIKI_TITLE = "Gas-optimized bucket-cache writeback clobbers storage on empty-array input"
    WIKI_DESCRIPTION = "To save SLOAD/SSTORE costs, reward/claim contracts cache a bitmap bucket locally, update it during iteration over user-supplied claim ids, then write the final cache back to storage. The pattern: `uint256 cachedBucket; uint256 cachedBitmap; for (...) { ... } storage[msg.sender][cachedBucket] = cachedBitmap;`. If no early-exit prevents the writeback on an empty input array, the uninitialized cached"
    WIKI_EXPLOIT_SCENARIO = "Attacker claims rewardIds [0..255] the normal way — storage[user][0] is set to max for their claimed bits. Attacker then calls claimRewards([]). The empty-array loop does nothing; the final writeback assigns storage[user][0] = 0. Attacker re-claims the same 0..255 rewards. Repeat indefinitely, draining the reward escrow."
    WIKI_RECOMMENDATION = "Require the input array be non-empty at entry (`if (ids.length == 0) revert EmptyArray();`) or guard the writeback with `if (ids.length > 0) storage[...][cachedBucket] = cachedBitmap;`. Additionally initialize cachedBucket from the first id before the loop."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(bucket|bitmap|packedClaims|claimedBitmap)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(claim|withdraw|settle|_get[A-Z][a-zA-Z]*)'}, {'function.body_contains_regex': 'for\\s*\\(\\s*uint256\\s+i\\s*=\\s*0\\s*;\\s*i\\s*<\\s*[a-zA-Z_0-9.]+\\.length\\s*;'}, {'function.body_contains_regex': '(cachedBucket|cachedBitmap|cachedClaimed)'}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '[a-zA-Z_0-9]+\\[msg\\.sender\\]\\[cached(Reward)?Bucket\\]\\s*=\\s*cached'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*[a-zA-Z_0-9.]+\\.length\\s*(>|!=)\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cached-bucket-writeback-without-empty-array-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
