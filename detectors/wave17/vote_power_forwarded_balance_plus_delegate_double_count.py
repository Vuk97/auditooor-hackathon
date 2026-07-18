"""
vote-power-forwarded-balance-plus-delegate-double-count - generated from reference/patterns.dsl/vote-power-forwarded-balance-plus-delegate-double-count.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-power-forwarded-balance-plus-delegate-double-count.yaml
Source: detector-lift-fire6-worker-vg-vote-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotePowerForwardedBalancePlusDelegateDoubleCount(AbstractDetector):
    ARGUMENT = "vote-power-forwarded-balance-plus-delegate-double-count"
    HELP = "Forwarded or carried vote power can be credited into the next period and then counted again through delegated power when the next-period vote receipt is not written."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-power-forwarded-balance-plus-delegate-double-count.yaml"
    WIKI_TITLE = "Forwarded vote balance plus delegate power can double count"
    WIKI_DESCRIPTION = "Vote carry-forward paths must mark the target period as voted before or while copying old pool weights. If prior-period weights are forwarded into a new period without setting the next-period receipt, the same token can remain free for delegate, split, merge, withdraw, or second-vote paths that consume the same voting units again. A related direct vote shape adds direct balance plus delegated power in one tally without a receipt."
    WIKI_EXPLOIT_SCENARIO = "A voter carries old pool weights into the next period. Because the carry-forward path calls the vote writer but leaves period[nextPeriod].voted[tokenId] false, the token can still enter another vote-affecting path and the forwarded weight plus delegated weight can be counted twice."
    WIKI_RECOMMENDATION = "Write or check the next-period voted receipt before crediting forwarded weights, and use one canonical voting-power source per proposal or period."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(vote|voting|proposal|period|epoch|delegate|delegat|gauge|pool|weight|power)'}, {'contract.source_matches_regex': '(?is)(carryVoteForward|carry.*vote.*forward|forward.*vote|copy.*vote|tokenIdVotedList|tokenIdVotes|_vote\\s*\\(|balanceOf|delegatedTo|delegatedPower|delegateVotes)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(carry.*vote.*forward|forward.*vote|copy.*vote|roll.*vote|reuse.*vote|cast.*vote|submit.*vote|record.*vote|vote|tally)'}, {'function.body_contains_regex': '(?is)((?:fromPeriod|_fromPeriod|previousPeriod|prevPeriod|sourcePeriod|oldPeriod|lastPeriod|tokenIdVotedList|tokenIdVotes|weightList|poolList).*?(?:_vote\\s*\\(|(?:forVotes|proposalVotes|poolVotes|gaugeVotes|tokenIdVotes|totalWeight)\\s*\\[[^\\]]+\\]\\s*(?:\\+=|=\\s*[^;\\n]*\\+))|(?:balanceOf|_balances|balances|votingBalance|baseVotes|forwardedVotes|forwardedPower|carriedVotes|carriedPower|periodVotes|tokenIdVotes)\\s*\\[[^\\]]+\\]\\s*\\+\\s*(?:delegatedTo|delegatedVotes|delegateVotes|delegatedPower|delegatePower|voteCheckpoints|checkpoints)\\s*\\[)'}, {'function.body_contains_regex': '(?is)(vote|vot|delegat|weight|power|period|proposal)'}, {'function.body_not_contains_regex': '(?is)(period\\s*\\[\\s*(?:nextPeriod|nextEpoch|nextRound|targetPeriod)\\s*\\]\\s*\\.\\s*voted\\s*\\[[^\\]]+\\]\\s*=\\s*true|voted\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=\\s*true|hasVoted\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=\\s*true|_checkPeriodVoted\\s*\\(|checkPeriodVoted\\s*\\(|_markVoted\\s*\\(|_writeVoteReceipt\\s*\\(|already\\s+voted|receipt\\s*\\.\\s*hasVoted)'}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - vote-power-forwarded-balance-plus-delegate-double-count: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
