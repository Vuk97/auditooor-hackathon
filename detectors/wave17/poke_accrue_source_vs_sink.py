"""
poke-accrue-source-vs-sink — generated from reference/patterns.dsl/poke-accrue-source-vs-sink.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py poke-accrue-source-vs-sink.yaml
Source: auditooor/RG-N5-narrowing-2026-05-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PokeAccrueSourceVsSink(AbstractDetector):
    ARGUMENT = "poke-accrue-source-vs-sink"
    HELP = "Reward-accrual SINK function (_mint / _deposit / _update / _redeem) writes share/balance state without calling the accrual SOURCE (poke / _accrueRewards) first. This breaks the per-user reward index invariant: the user's accrued reward at the prior index is silently retired when the new mint changes"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/poke-accrue-source-vs-sink.yaml"
    WIKI_TITLE = "Reward-accrual SINK mints/redeems shares without invoking accrual SOURCE"
    WIKI_DESCRIPTION = "A reward distribution system computes per-user rewards as `reward = balance * (currentIndex - lastUserIndex)`. Every function that mutates `balance` (mint, deposit, redeem, withdraw) MUST first invoke the accrual SOURCE (`_accrueRewards(user)` / `poke(user)` / `_updateRewardIndex(user)`) so the unclaimed reward at the OLD balance is checkpointed before the balance changes. When a SINK function cha"
    WIKI_EXPLOIT_SCENARIO = "(1) Alice has stake = 100 since index = 0. Index advances to 50. (2) Alice calls `unstake(50)` — but `unstake()` is a SINK that does NOT call `_accrueRewards(alice)` first. (3) Storage update: `balanceOf[alice] = 50`, `lastUserIndex[alice] = 50` (lazy update at next pull). (4) On Alice's next claim: reward = 50 * (50 - 50) = 0. Alice's pending reward of `100 * 50 = 5000` was retired. Repeat for ev"
    WIKI_RECOMMENDATION = "Wrap every balance-changing SINK with the accrual modifier or call `_accrueRewards(user)` as the FIRST line of the SINK body. Use a single canonical modifier (e.g., `nonReentrant accrue(user)`) and apply it consistently to mint, deposit, redeem, withdraw, transfer, transferFrom, and any custom mutat"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(reward|accrual|index|share|totalSupply|rewardPerShare)'}, {'contract.has_function_body_matching': '(_accrue|accrueRewards|_updateRewardIndex|poke\\s*\\()'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(_mint|mint|_deposit|deposit|_update|_redeem|redeem|withdraw|stake|unstake)'}, {'function.writes_storage_matching': '(balance|share|totalSupply|_balances|stake)'}, {'function.body_not_contains_regex': '(_accrue|accrueRewards|_updateRewardIndex|poke\\s*\\(|pokeRewards|claimAndUpdate)'}, {'function.body_not_contains_regex': '(?i)\\bfunction\\s+(_?accrueRewards|_?poke|_?updateRewardIndex)\\s*\\('}, {'function.is_mutating': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — poke-accrue-source-vs-sink: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
