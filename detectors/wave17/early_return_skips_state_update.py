"""
early-return-skips-state-update — generated from reference/patterns.dsl/early-return-skips-state-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py early-return-skips-state-update.yaml
Source: code4arena-2025-08-morpheus-M-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EarlyReturnSkipsStateUpdate(AbstractDetector):
    ARGUMENT = "early-return-skips-state-update"
    HELP = "Reward / yield distributor has an `if (rewards == 0) return;` short-circuit before advancing its checkpoint (lastUnderlyingBalance / lastUpdate / lastIndex) — once the zero branch triggers once (e.g. after maxEndTime), all subsequent accruals are stranded because the checkpoint never moves forward."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/early-return-skips-state-update.yaml"
    WIKI_TITLE = "Reward distributor early-returns before advancing its checkpoint"
    WIKI_DESCRIPTION = "Reward / yield distributors typically maintain a checkpoint state var (`lastUnderlyingBalance`, `lastUpdate`, `lastIndex`) that records the accounting cursor. On every call, the contract computes the delta against the current balance, transfers the reward, and writes the new checkpoint. When the function is implemented with an early-return branch — `if (periodRewards == 0) return;` — that short-ci"
    WIKI_EXPLOIT_SCENARIO = "Morpheus Yield Vault accrues yield-bearing token rewards with `maxEndTime` = epoch_N. (1) During epoch N, users stake and the distributor updates `lastUnderlyingBalance` on each call. (2) Epoch N+1 arrives; `periodRewards` is now 0 because the distribution window closed. `distributeRewards()` returns on the first line. (3) The underlying vault still accrues yield (stETH rebases, yield-bearing toke"
    WIKI_RECOMMENDATION = "Advance the checkpoint unconditionally before any early-return short-circuit, even when the reward amount is zero. Pattern: `uint256 cur = currentBalance(); lastUnderlyingBalance = cur; if (periodRewards == 0) return; /* transfer rewards */`. Alternatively, make the function idempotent by moving the"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'lastUnderlyingBalance|lastUpdate|lastBalance|lastAccrual|lastRewardTime|lastDistribution|lastIndex|lastSnapshot'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(distribute|accrue|update|harvest|checkpoint|claim)\\w*Reward|^distribute$|^accrueReward|^_updateReward|^update\\w*Index|^refreshReward|^syncReward'}, {'function.writes_storage_matching': 'lastUnderlyingBalance|lastUpdate|lastBalance|lastAccrual|lastRewardTime|lastDistribution|lastIndex|lastSnapshot'}, {'function.body_contains_regex': {'regex': 'if\\s*\\([^)]*(periodRewards|rewardAmount|reward|amount|pending|delta|accrued)[^)]*==\\s*0[^)]*\\)\\s*(return|\\{\\s*return)|if\\s*\\(\\s*(periodRewards|rewardAmount|reward|pending|delta|accrued)\\s*==\\s*0\\s*\\)\\s*return'}}, {'function.body_not_contains_regex': '(lastUnderlyingBalance|lastUpdate|lastBalance|lastAccrual|lastRewardTime|lastDistribution|lastIndex)\\s*=\\s*[^;]+;[\\s\\n]*if\\s*\\([^)]*==\\s*0[^)]*\\)\\s*return|_updateLast\\w*\\(\\s*\\)\\s*;[\\s\\n]*if\\s*\\([^)]*==\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — early-return-skips-state-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
