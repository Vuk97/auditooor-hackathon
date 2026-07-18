"""
bucket-cache-missing-first-iteration-init — generated from reference/patterns.dsl/bucket-cache-missing-first-iteration-init.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bucket-cache-missing-first-iteration-init.yaml
Source: auditooor-R75-nethermind-royco-vaults-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BucketCacheMissingFirstIterationInit(AbstractDetector):
    ARGUMENT = "bucket-cache-missing-first-iteration-init"
    HELP = "A cached-bucket loop initializes the cached *bitmap* on the first iteration but forgets to initialize the cached *bucket index* (cachedBucket stays 0). On the next iteration, if rewardIds[1]/256 != 0, the else-branch writes the newly-loaded bitmap back to storage at cachedBucket=0 — zeroing bucket 0"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bucket-cache-missing-first-iteration-init.yaml"
    WIKI_TITLE = "Bucket-cache loop initializes the bitmap but not the bucket index on first iteration"
    WIKI_DESCRIPTION = "Paired with 'cached-bucket-writeback-without-empty-array-guard', this is the second edge case. The intended pattern keeps (cachedBucket, cachedBitmap) in sync so the writeback always targets the right bucket. Authors commonly write: `if (i == 0) cachedBitmap = storage[user][rewardBucket]; else if (cachedBucket != rewardBucket) { storage[user][cachedBucket] = cachedBitmap; cachedBucket = rewardBuck"
    WIKI_EXPLOIT_SCENARIO = "Attacker constructs rewardIds = [300, 10]. Iteration 0 loads bucket (300/256 = 1) into cachedBitmap, leaves cachedBucket = 0. Iteration 1: rewardBucket = 0, else-branch fires because cachedBucket(0) != rewardBucket(0)? No — same bucket. OK. Try rewardIds = [300, 600]: iter 0 bitmap = bucket[1], cachedBucket still 0; iter 1 rewardBucket=2, else-branch writes `storage[user][0] = bitmap_of_bucket_1`,"
    WIKI_RECOMMENDATION = "In the i==0 branch, also assign `cachedBucket = rewardBucket` (or `cachedBucket = rewardIds[0]/256`). Alternatively move the cache write-back outside the loop entirely and pre-compute a distinct bucket list before iteration."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(bucket|bitmap|packedClaims|claimedBitmap)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '^(claim|claimRewards|claimForMany|_getEpochRange|_getEpochRangeAndUpdate|_process|_processClaim|_update|_updateCache)$'}, {'function.body_contains_regex': 'if\\s*\\(\\s*i\\s*==\\s*0\\s*\\)\\s*\\{\\s*\\n?\\s*cached(Claimed|Bitmap|Rewards)'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*i\\s*==\\s*0\\s*\\)\\s*\\{[^{}]*cachedBucket\\s*='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bucket-cache-missing-first-iteration-init: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
