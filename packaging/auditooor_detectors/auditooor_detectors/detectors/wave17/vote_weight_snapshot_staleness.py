"""
vote-weight-snapshot-staleness — generated from reference/patterns.dsl/vote-weight-snapshot-staleness.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-weight-snapshot-staleness.yaml
Source: solodit-cluster/cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VoteWeightSnapshotStaleness(AbstractDetector):
    ARGUMENT = "vote-weight-snapshot-staleness"
    HELP = "Governance vote function reads current balanceOf(msg.sender) rather than a historical snapshot (getPriorVotes / getPastVotes / snapshot / checkpoint / _getVotingPower / votingPowerAt) — flash-loan voting power acquisition is possible."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-weight-snapshot-staleness.yaml"
    WIKI_TITLE = "Governance vote weight read from current balance (no snapshot) — flash-loan vote manipulation"
    WIKI_DESCRIPTION = "A state-mutating vote / castVote / submitVote / voteFor / _castVote / _applyVote function on a contract that holds gauge / votes / voting / voter / delegatee storage reads the voter's CURRENT balance via balanceOf(msg.sender), balances[msg.sender], or token.balanceOf(...) to determine vote weight, but does not read the balance at a historical snapshot (Compound/OZ Governor's getPriorVotes / getPas"
    WIKI_EXPLOIT_SCENARIO = "Governance contract `G` exposes `vote(uint256 proposalId, bool support)` that reads `weight = token.balanceOf(msg.sender)` at call time. Attacker M executes a single transaction that: (1) flash-borrows 10M GOV tokens from a DEX, (2) calls `G.vote(42, yes)` — G reads M's balance as 10M and records a 10M-weight YES vote, (3) repays the flash loan. The cost to M is the flash-loan fee; the malicious p"
    WIKI_RECOMMENDATION = "Replace the live balance read with a snapshot primitive: (a) Compound/OZ Governor's `token.getPastVotes(account, proposalSnapshotBlock)` or `getPriorVotes(account, block)`, (b) ERC20Snapshot's `token.balanceOfAt(account, snapshotId)` taken at proposal creation, (c) ERC20Votes's `token.votingPowerAt("

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'gauge|votes|voting|voter|delegatee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'vote|castVote|_castVote|submitVote|voteFor|_applyVote'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*(msg\\.sender|voter)|balances\\s*\\[\\s*msg\\.sender|\\.balanceOf\\s*\\('}, {'function.body_not_contains_regex': 'getPriorVotes|getPastVotes|snapshot|_getVotingPower|checkpoint|\\.votingPowerAt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vote-weight-snapshot-staleness: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
