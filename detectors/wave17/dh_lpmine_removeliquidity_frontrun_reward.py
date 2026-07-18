"""
dh-lpmine-removeliquidity-frontrun-reward — generated from reference/patterns.dsl/dh-lpmine-removeliquidity-front-run-reward.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-lpmine-removeliquidity-front-run-reward.yaml
Source: defihacklabs/LPMine-2025-01+98Token-2025-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhLpmineRemoveliquidityFrontrunReward(AbstractDetector):
    ARGUMENT = "dh-lpmine-removeliquidity-frontrun-reward"
    HELP = "Deposit then withdraw in same block or adjacent block harvests rewards without economic commitment."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-lpmine-removeliquidity-front-run-reward.yaml"
    WIKI_TITLE = "Deposit-without-lock lets same-block reward harvesting"
    WIKI_DESCRIPTION = "Masterchef-style reward pools accrue `accRewardPerShare` over time. If a deposit has no lock period and `updatePool` is called on deposit, user can sandwich reward-emission with (deposit, emission, withdraw) even if their capital was at risk for 0 seconds, stealing reward from longer-committed stakers."
    WIKI_EXPLOIT_SCENARIO = "LPMine 2025-01 and 98Token 2025-01: no per-user lock on deposit. Attacker front-ran the emission function, deposited max, ran harvest, withdrew — stealing a share of emission proportional to their momentary balance."
    WIKI_RECOMMENDATION = "Add `lastDepositBlock[user] = block.number` and enforce `withdraw` reverts unless `block.number > lastDepositBlock[user] + MIN_LOCK`. Or accrue rewards based on time-weighted balances."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'updatePool|accRewardPerShare|removeLiquidity|deposit|withdraw'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|stake|addLiquidity)$'}, {'function.body_contains_regex': 'updatePool|_updateRewards|accRewardPerShare'}, {'function.body_not_contains_regex': 'lockedUntil|depositLockPeriod|minStakeDuration|lastDepositBlock'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-lpmine-removeliquidity-frontrun-reward: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
