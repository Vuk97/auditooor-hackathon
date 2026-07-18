"""
voting-power-self-delegation-double-count - generated from reference/patterns.dsl/voting-power-self-delegation-double-count.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py voting-power-self-delegation-double-count.yaml
Source: lane-s3-solidity-recall-lift-2026-06-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotingPowerSelfDelegationDoubleCount(AbstractDetector):
    ARGUMENT = "voting-power-self-delegation-double-count"
    HELP = "Vote weight adds a caller balance to delegated or checkpointed power while self-delegation and repeat voting are not excluded."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/voting-power-self-delegation-double-count.yaml"
    WIKI_TITLE = "Self-delegation can double-count direct and delegated voting power"
    WIKI_DESCRIPTION = "Governance vote paths that add a voter's direct balance to delegated or checkpointed power must ensure the delegated source cannot be the same account and must record one vote per proposal. If self-delegation is allowed, the same voting units can be counted as both direct balance and delegated checkpoint power."
    WIKI_EXPLOIT_SCENARIO = "A voter delegates to themselves, then calls the proposal vote function. The function reads the caller's direct token balance and also reads the checkpointed delegate power through the caller's delegate slot. Because the delegate slot points back to the caller and no per-proposal vote receipt is written, the proposal can receive the same voting units twice or more."
    WIKI_RECOMMENDATION = "Use one canonical snapshotted voting-power source per proposal, reject self-delegation or normalize it to zero extra delegated power, and write `hasVoted[proposalId][voter] = true` before adding weight."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(delegate|delegation|voting|proposal|ballot)'}, {'contract.source_matches_regex': '(?i)(checkpoint|delegateVotes|delegatedPower|votingPower)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(castBallot|castVote|submitVote|vote|recordVote|tally)'}, {'function.body_contains_regex': '(?is)(?:_balances|balances|votingBalance|baseVotes)\\s*\\[\\s*(?:voter|account|msg\\.sender)\\s*\\]\\s*\\+\\s*(?:voteCheckpoints|checkpoints|delegateVotes|delegatedPower)\\s*\\['}, {'function.body_contains_regex': '(?i)(delegates|delegateOf|representativeOf)\\s*\\['}, {'function.body_not_contains_regex': '(?i)(hasVoted|votedByProposal|proposalVoter|receipt\\.hasVoted)'}, {'function.contract.not_source_matches_regex': '(?i)(delegatee|newDelegate|representative)\\s*!=\\s*(?:msg\\.sender|voter|account)'}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

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
                info = [f, f" - voting-power-self-delegation-double-count: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
