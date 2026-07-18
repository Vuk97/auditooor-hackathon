"""
vote-double-count-stale-source-retention - generated from reference/patterns.dsl/vote-double-count-stale-source-retention.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-double-count-stale-source-retention.yaml
Source: capability-lift-p1-05-vote-double-count
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VoteDoubleCountStaleSourceRetention(AbstractDetector):
    ARGUMENT = "vote-double-count-stale-source-retention"
    HELP = "Voting or delegation accounting can retain a stale source and add the same stake, vote, or validator weight more than once."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-double-count-stale-source-retention.yaml"
    WIKI_TITLE = "Vote or delegation source retained across reassignment can be counted twice"
    WIKI_DESCRIPTION = "Governance and validator tally paths must maintain a single canonical source for each voting unit. If a reassignment, self-delegation, revote, merge, split, or validator update appends or adds the new source without debiting or clearing the old source, proposal tallies and quorum calculations can count the same stake twice."
    WIKI_EXPLOIT_SCENARIO = "A voter delegates a voting source, reassigns it, and triggers a vote or revote. The contract appends the source to the new delegate or adds its weight to the proposal tally while the old delegate, checkpoint, or validator-weight source remains live. The proposal then sees the same voting units through multiple accounting paths."
    WIKI_RECOMMENDATION = "Use one canonical snapshotted voting-power source per proposal. On reassignment, debit or remove the old source before crediting the new one, reject or normalize self-delegation, refresh validator weight before tallying, and write a per-proposal vote receipt before adding weight."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(vote|delegat|validator|quorum|proposal|tally|checkpoint|snapshot|votingPower|votePower|weight)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(cast.*vote|cast.*ballot|submit.*vote|submit.*ballot|record.*vote|record.*ballot|vote|ballot|tally|quorum|delegate|redelegate|setDelegate|changeDelegate|moveDelegation|poke|revote|merge|split|updateValidator|changeBalance)'}, {'function.body_contains_regex': '(?is)(\\+=|\\.push\\s*\\(|=\\s*[^;\\n]*(?:\\+|add\\s*\\())'}, {'function.body_contains_regex': '(?is)(vote|delegat|validator|quorum|proposal|tally|snapshot|checkpoint|weight|power)'}, {'function.body_contains_regex': '(?is)(oldDelegate|currentDelegate|previousDelegate|delegatedTo|delegates\\s*\\[|delegateOf|representativeOf|self|msg\\.sender|revote|poke|merge|split|validator|votePower|votingPower|checkpoint|snapshot)'}, {'function.body_not_contains_regex': '(?is)(hasVoted|receipt\\s*\\.\\s*hasVoted|already\\s+voted|_removeDelegation|removeDelegation|clearOldDelegate|detachDelegate|swapAndPop|swap\\s+and\\s+pop|_moveDelegateVotes\\s*\\([^;]*(delegation|delegateOf)|_refreshValidator|refreshValidator|syncValidator|updateValidatorPower|totalVoting\\s*-=\\s*|votePower\\s*\\[[^\\]]+\\]\\s*=\\s*0|delete\\s+delegated)'}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" - vote-double-count-stale-source-retention: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
