"""
checkpoint-same-block-returns-first — generated from reference/patterns.dsl/checkpoint-same-block-returns-first.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py checkpoint-same-block-returns-first.yaml
Source: solodit/sherlock/telcoin-H1-3632
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CheckpointSameBlockReturnsFirst(AbstractDetector):
    ARGUMENT = "checkpoint-same-block-returns-first"
    HELP = "Historical checkpoint lookup (getAtBlock / getPastVotes) is used to size rewards, but the stake/exit path permits both in the same block, letting a flashloaner create two checkpoints with the first showing inflated balance. Lookup returns the inflated value."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/checkpoint-same-block-returns-first.yaml"
    WIKI_TITLE = "Same-block checkpoint lookup rewards flashloan stake-exit loops"
    WIKI_DESCRIPTION = "OpenZeppelin-style `Checkpoints` records (block, value) tuples and returns the last tuple ≤ target block. When multiple tuples exist at the same block, many implementations return the first (deposit), not the last (exit). If a protocol computes rewards or voting power off `getAtBlock(user, sameBlock)` — e.g., because rewards are claimed in the same block the user enters — a flashloan lets the atta"
    WIKI_EXPLOIT_SCENARIO = "Staking contract distributes rewards proportional to `getAtBlock(user, block.number)` on claim. Attacker: (1) flashloans 100M TEL; (2) `stake(100M)` — checkpoint #0 at block N, balance 100M; (3) `claimRewards()` — reads checkpoint #0, attributes huge share; (4) `exit()` — checkpoint #1 at block N, balance 0; (5) repay flashloan. Protocol's reward pool is drained by one TX."
    WIKI_RECOMMENDATION = "In the stake path, enforce `require(block.number > lastActionBlock[user])` so any entry and exit cannot land in the same block. Alternatively, in the reward-reading path, reject same-block reads: `require(block.number > checkpointBlock)`. Document clearly whether `getAtBlock` returns first or last d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'Checkpoint|_checkpoints|checkpoints'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.getAtBlock\\s*\\(|getPastVotes\\s*\\(|getPriorVotes\\s*\\(|checkpointAt\\s*\\('}, {'function.body_contains_regex': '(reward|share|weight|payout|distribute|slash)\\s*=\\s*[^;]*getAt'}, {'contract.has_func_body_matching': 'require\\s*\\([^)]*(block\\.number|block\\.timestamp)\\s*>\\s*(last|start|depositedAt|stakedAt|enteredAt)'}, {'contract.has_func_body_matching_invert': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — checkpoint-same-block-returns-first: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
