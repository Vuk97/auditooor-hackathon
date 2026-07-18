"""
batch-claim-deferred-checkpoint-duplicate-input — generated from reference/patterns.dsl/batch-claim-deferred-checkpoint-duplicate-input.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py batch-claim-deferred-checkpoint-duplicate-input.yaml
Source: slice44-realworld-recall-provider-burn
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BatchClaimDeferredCheckpointDuplicateInput(AbstractDetector):
    ARGUMENT = "batch-claim-deferred-checkpoint-duplicate-input"
    HELP = "Batch claim/redeem loops over caller-supplied duplicate ids/tokens while cumulative/checkpoint accounting is synchronized only after or outside the duplicate-sensitive claim path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/batch-claim-deferred-checkpoint-duplicate-input.yaml"
    WIKI_TITLE = "Batch claim accepts duplicate ids before checkpoint synchronization"
    WIKI_DESCRIPTION = "Reward and fee claimers often compute owed value from a cumulative accumulator and a per-user/per-id checkpoint. If a public batch entrypoint loops over a caller-supplied id/token array and forwards each element into a claim helper without first enforcing uniqueness, repeated entries can reuse the same stale checkpoint observation. The core state-change-between-check-and-use failure is that the fi"
    WIKI_EXPLOIT_SCENARIO = "A user has one token with 100 units claimable. They call `batchClaim([token, token])`. The first iteration observes `lastCheckpoint[user][token]` and credits 100. Because the batch path does not deduplicate and checkpoint synchronization is deferred or missing in the duplicate-sensitive path, the second iteration can observe the same claimable state and credit another 100."
    WIKI_RECOMMENDATION = "Reject duplicate ids/tokens at the batch entrypoint with a seen set, sorted-unique requirement, or `_requireUnique` helper. Also update the per-id checkpoint inside the same iteration before any transfer/credit side effect. Add a regression test proving duplicate input is equivalent to a single inpu"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(lastCheckpoint|checkpoint|rewardDebt|nextRedeem|lastClaim|cumulativePerToken|cumulative|claimable|accrued)'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^(batchClaim|claimBatch|claimMultiple|multiClaim|redeemBatch|redeemMultiple)$'}, {'function.body_contains_regex': '(?i)for\\s*\\([^)]*\\w+\\s*<\\s*\\w+\\s*\\.length'}, {'function.body_contains_regex': '(?i)(_claim|claim|_redeem|redeem)\\s*\\(\\s*\\w+\\s*\\[\\s*i\\s*\\]'}, {'function.body_not_contains_regex': '(?i)(_requireUnique|containsDuplicate|dedup|unique|EnumerableSet|seen\\s*\\[|visited\\s*\\[|require\\s*\\([^)]*\\w+\\s*\\[\\s*i\\s*\\]\\s*!=\\s*\\w+\\s*\\[\\s*j\\s*\\]|require\\s*\\([^)]*\\w+\\s*\\[\\s*i\\s*\\]\\s*>\\s*\\w+\\s*\\[\\s*i\\s*-\\s*1\\s*\\])'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — batch-claim-deferred-checkpoint-duplicate-input: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
