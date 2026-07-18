"""
reward-distribution-duplicate-ids-before-debt-update — generated from reference/patterns.dsl/reward-distribution-duplicate-ids-before-debt-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-distribution-duplicate-ids-before-debt-update.yaml
Source: solodit/halborn/story-52385
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardDistributionDuplicateIdsBeforeDebtUpdate(AbstractDetector):
    ARGUMENT = "reward-distribution-duplicate-ids-before-debt-update"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: read-only reward helper computes per-ID rewards against rewardDebt before the write pass updates debt. Duplicates in the ID array each receive the full reward."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-distribution-duplicate-ids-before-debt-update.yaml"
    WIKI_TITLE = "Two-pass reward helper lets duplicate IDs collect full reward each time"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A reward distributor splits per-member reward evenly and then debits each member's `rewardDebt` so the same share is not paid twice. The per-member quotient is computed in a read-only helper pass, and debts are written in the caller's write pass. If the same member ID appears multiple times in the input array, the helper re-computes the full"
    WIKI_EXPLOIT_SCENARIO = "Group has 3 IPs and 15 ETH royalty to distribute. IP1 owner calls `claimReward(group, token, [IP1, IP1, IP1])`. The read pass returns `[5, 5, 5]` because rewardDebt is zero for all three passes. The later write pass transfers three rewards and only then increments debt. IP1 receives the entire pool."
    WIKI_RECOMMENDATION = "Combine the read and write into a single pass: compute reward for `ipIds[i]`, then immediately `rewardDebt[ipIds[i]] += rewards[i]`. Alternatively, dedupe the input array up front with a scratch mapping or sorted-unique assertion. Add an invariant test that duplicated IDs revert or are equivalent to"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(rewardDebt|rewardDebts|claimReward|distributeReward|ipIds|memberIds|tokenIds)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_ordered_regex': {'first': 'for\\s*\\(\\s*uint\\w*\\s+i\\s*=\\s*0\\s*;\\s*i\\s*<\\s*\\w+\\.length', 'second': '(reward|payout|amount)\\w*\\s*\\[\\s*i\\s*\\]\\s*=\\s*\\w+\\s*-\\s*\\w+(Debt|Paid|Claimed)', 'ignore_comments_and_strings': True}}, {'function.body_not_contains_regex': '\\w+Debt\\s*\\[[^]]+\\]\\s*\\+=\\s*reward\\w*\\[\\s*i\\s*\\]|\\w+Debt\\s*\\[[^]]+\\]\\s*=\\s*\\w+PerIP'}, {'function.body_not_contains_regex': 'seen\\[|visited\\[|require\\s*\\([^)]*!=\\s*\\w+\\[\\s*i\\s*-\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-distribution-duplicate-ids-before-debt-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
