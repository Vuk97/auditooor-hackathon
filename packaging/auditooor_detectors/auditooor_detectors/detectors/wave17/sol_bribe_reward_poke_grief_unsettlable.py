"""
sol-bribe-reward-poke-grief-unsettlable — generated from reference/patterns.dsl/sol-bribe-reward-poke-grief-unsettlable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-bribe-reward-poke-grief-unsettlable.yaml
Source: solodit-cluster-C0311
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolBribeRewardPokeGriefUnsettlable(AbstractDetector):
    ARGUMENT = "sol-bribe-reward-poke-grief-unsettlable"
    HELP = "Permissionless `poke` on bribe voter can grief users or lock rewards."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-bribe-reward-poke-grief-unsettlable.yaml"
    WIKI_TITLE = "Permissionless voter `poke` griefs bribe rewards"
    WIKI_DESCRIPTION = "Bribe systems checkpoint voter power via `poke`; if anyone can call it on another user's position, attacker can move the checkpoint to a disadvantageous block (bribe just claimed, or just before reward top-up), locking the victim out of the round's payout or stuck in a stale snapshot permanently."
    WIKI_EXPLOIT_SCENARIO = "Velodrome/Thena C0311: attacker called `Voter.poke(victim)` after bribe claim but before the next round started, forcing the victim's voting-power snapshot to a point where their vote was counted toward the FINISHED round — rewards for the current round forfeited."
    WIKI_RECOMMENDATION = "Restrict `poke` to `msg.sender == user` or the VotingEscrow contract. For emergency admin poking, gate with `onlyGovernance`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'poke|checkpoint|Voter|Bribe|VotingEscrow'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(poke|checkpoint|updateSnapshot|updateVoting|sync)$'}, {'function.body_contains_regex': 'snapshot|lastVoted|_checkpointBribe|rewardPerVote'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyGovernance', 'onlyAuthorized', 'onlyVoter'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(ve|votingEscrow|voter|authorized)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-bribe-reward-poke-grief-unsettlable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
