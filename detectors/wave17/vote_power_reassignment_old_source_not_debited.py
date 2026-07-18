"""
vote-power-reassignment-old-source-not-debited - generated from reference/patterns.dsl/vote-power-reassignment-old-source-not-debited.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-power-reassignment-old-source-not-debited.yaml
Source: detector-lift-fire4-worker-va-vote-double-count
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotePowerReassignmentOldSourceNotDebited(AbstractDetector):
    ARGUMENT = "vote-power-reassignment-old-source-not-debited"
    HELP = "Vote power reassignment credits or appends a new vote source without debiting the old source."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-power-reassignment-old-source-not-debited.yaml"
    WIKI_TITLE = "Vote power reassignment leaves old source vote power live"
    WIKI_DESCRIPTION = "A vote power reassignment reads the old delegate or vote source, writes a new source, and then credits the new source ledger or appends to the new delegate list without debiting or removing the old source. The same voting units can remain live under the previous source and also be counted under the new source."
    WIKI_EXPLOIT_SCENARIO = "A voter with power assigned to source A is reassigned to source B. The contract credits or appends source B but never subtracts or removes the source from source A, so a tally that reads both source paths can count one deposit twice."
    WIKI_RECOMMENDATION = "Debit or remove the old source before crediting the new source, or route every reassignment through one move-vote-power helper that enforces debit-before-credit ordering."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(voteSourceOf|delegateOf|delegates|voteDelegate|delegatedTo)'}, {'contract.source_matches_regex': '(?is)(votePowerBySource|delegatedVotes|delegateVotes|votingPower|votePower|delegateSources|delegatedTokenIds)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|setDelegate|updateDelegate|changeDelegate|reassignVoteSource|setVoteSource|moveVoteSource)$'}, {'function.body_contains_regex': '(?is)(?:address|uint256)\\s+(oldSource|oldDelegate|previousSource|previousDelegate|currentSource|currentDelegate)\\s*=\\s*(voteSourceOf|delegateOf|delegates|voteDelegate|delegatedTo)\\s*\\['}, {'function.body_contains_regex': '(?is)(voteSourceOf|delegateOf|delegates|voteDelegate|delegatedTo)\\s*\\[[^\\]]+\\]\\s*=\\s*(newSource|newDelegate|delegatee|to|toTokenId|representative)'}, {'function.body_contains_regex': '(?is)((votePowerBySource|delegatedVotes|delegateVotes|votingPower|votePower)\\s*\\[\\s*(newSource|newDelegate|delegatee|to|toTokenId|representative)\\s*\\]\\s*\\+=|(delegateSources|delegatedTokenIds)\\s*\\[\\s*(newSource|newDelegate|delegatee|to|toTokenId|representative)\\s*\\]\\s*\\.\\s*push\\s*\\()'}, {'function.body_not_contains_regex': '(?is)(votePowerBySource|delegatedVotes|delegateVotes|votingPower|votePower)\\s*\\[\\s*(oldSource|oldDelegate|previousSource|previousDelegate|currentSource|currentDelegate)\\s*\\]\\s*-='}, {'function.body_not_contains_regex': '(?is)(_moveVotePower|_moveDelegateVotes|_moveDelegates|_debitOldSource|_debitDelegate|_removeDelegateVotes|removeDelegation|clearOldDelegate|clearOldVoteSource|debitVoteSource|swapAndPop|pop)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - vote-power-reassignment-old-source-not-debited: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
