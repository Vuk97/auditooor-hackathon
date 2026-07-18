"""
w68-optimistic-governor-poison-no-window - generated from reference/patterns.dsl/w68-optimistic-governor-poison-no-window.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-optimistic-governor-poison-no-window.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68OptimisticGovernorPoisonNoWindow(AbstractDetector):
    ARGUMENT = "w68-optimistic-governor-poison-no-window"
    HELP = "Optimistic governor consumes mutable proposal state without the window, snapshot, or voter-invalidation guard that keeps poisoned proposals from landing"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-optimistic-governor-poison-no-window.yaml"
    WIKI_TITLE = "Optimistic governor proposal, vote, or execution path consumes poisoned mutable state"
    WIKI_DESCRIPTION = "An optimistic governance flow consumes proposal state to execute a call, install a queued update, update a proposal payload, or count votes. The class invariant is that the final consumer must bind to a clean commitment point: liveness window elapsed, proposal unchallenged and uncancelled, stale payloads invalidated for voters, and vote weight read from a past snapshot. The vulnerable shape skips "
    WIKI_EXPLOIT_SCENARIO = "Optimistic governor consumes mutable proposal state without the window, snapshot, or voter-invalidation guard that keeps poisoned proposals from landing"
    WIKI_RECOMMENDATION = "Before execution or installation, require the challenge/liveness window to have elapsed cleanly and the proposal to remain unchallenged, uncancelled, and current. If the payload can be updated, invalidate voter notice or bump a proposal version/nonce. If votes are counted later, read voting power fr"

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(proposal|proposals|payload|selector|challeng|dispute|liveUntil|readyAt|eta|queued|pending|snapshot|vote|votingPower|balance|checkpoint|version|notice)'}, {'contract.source_matches_regex': '(?i)(govern|proposal|optimistic|selector|payload|challeng|dispute|timelock|snapshot|vote)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches_regex': '^(execute|executeProposal|finalize|finalizeProposal|applyProposal|approveProposal|resolveProposal|enactProposal|propose|createProposal|submitProposal|updateProposal|castVote|vote|voteOnProposal)$'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(Proposal\\s+(storage|memory)|proposals\\s*\\[|_proposals\\s*\\[|proposalPayloads\\s*\\[|pendingProposal|queuedProposal|proposalPayloadHash\\s*\\[|payloadHash\\s*\\[)'}, {'function.body_contains_regex': '(?i)(\\.call\\s*\\(|\\.\\s*set[A-Z][A-Za-z0-9_]*\\s*\\(|grantRole\\s*\\(|approve\\s*\\(|proposalPayloadHash\\s*\\[[^\\]]+\\]\\s*=|payloadHash\\s*\\[[^\\]]+\\]\\s*=|\\.(payloadHash|proposalHash)\\s*=|snapshot(Block)?\\s*=\\s*(block\\.number|clock\\(\\))|startBlock\\s*=\\s*block\\.number|proposalSnapshot\\s*=\\s*block\\.number|\\b(balanceOf|getVotes)\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(challenged|unchallenged|dispute(Window|Period)?|liveUntil|readyAt|eta|delayEnd|gracePeriod|cancell?ed|block\\.timestamp\\s*>=\\s*.*(liveUntil|readyAt|eta|delayEnd)|state\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*ProposalState\\.(Succeeded|Queued)|proposal(State|Version|Nonce|Salt)|currentHash|expectedHash|operationId|voterNotice|noticeInvalidat|invalidate.*voter|block\\.number\\s*-\\s*1|clock\\(\\)\\s*-\\s*1|getPastVotes|balanceAt|votesAt)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - w68-optimistic-governor-poison-no-window: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
