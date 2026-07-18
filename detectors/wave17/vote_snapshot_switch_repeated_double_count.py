"""
vote-snapshot-switch-repeated-double-count - generated from reference/patterns.dsl/vote-snapshot-switch-repeated-double-count.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-snapshot-switch-repeated-double-count.yaml
Source: fire4-vb-solodit-21332-nouns-dao
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VoteSnapshotSwitchRepeatedDoubleCount(AbstractDetector):
    ARGUMENT = "vote-snapshot-switch-repeated-double-count"
    HELP = "A governance vote snapshot switch can be set repeatedly after proposals already exist, changing which block supplies voting power and letting historical votes be counted under inconsistent snapshots."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-snapshot-switch-repeated-double-count.yaml"
    WIKI_TITLE = "Repeated vote snapshot switch can double count voting power"
    WIKI_DESCRIPTION = "Vote accounting that switches from one snapshot block rule to another must treat the switch as one-time state. If the switch proposal id can be moved forward repeatedly, already cast votes and future votes for the same proposal can use different voting-power timestamps. A token transfer between those timestamps can make the same voting unit count once for the old holder and once for the new holder."
    WIKI_EXPLOIT_SCENARIO = "Bob transfers governance tokens to Alice between a proposal start block and its creation block. Alice votes before the snapshot switch is moved. The admin path moves `voteSnapshotBlockSwitchProposalId` again, so Bob can vote after the switch using the other snapshot rule. The same underlying tokens are counted twice on the same proposal."
    WIKI_RECOMMENDATION = "Make the vote snapshot switch one-time. Revert when `voteSnapshotBlockSwitchProposalId` is already set, or persist the exact snapshot mode per proposal so later switch changes cannot alter vote accounting for existing proposals."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(voteSnapshotBlockSwitchProposalId|creationBlock|startBlock|proposalCount)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(set.*vote.*snapshot.*switch|set.*snapshot.*proposal|voteSnapshotBlockSwitchProposalId)'}, {'function.source_matches_regex': '(?is)voteSnapshotBlockSwitchProposalId'}, {'function.source_matches_regex': '(?is)proposalCount\\s*\\+\\s*1'}, {'function.source_matches_regex': '(?is)voteSnapshotBlockSwitchProposalId\\s*=\\s*(newVoteSnapshotBlockSwitchProposalId|[^;\\n]*proposalCount\\s*\\+\\s*1)'}, {'function.not_source_matches_regex': '(?is)(VoteSnapshotSwitchAlreadySet|SnapshotSwitchAlreadySet|AlreadySet|if\\s*\\([^)]*(oldVoteSnapshotBlockSwitchProposalId|voteSnapshotBlockSwitchProposalId)\\s*(>|!=)\\s*0[^)]*\\)\\s*\\{?\\s*(revert|return)|require\\s*\\([^;]*(oldVoteSnapshotBlockSwitchProposalId|voteSnapshotBlockSwitchProposalId)\\s*==\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

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
                info = [f, f" - vote-snapshot-switch-repeated-double-count: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
