"""
delegation-reassignment-stale-vote-source - generated from reference/patterns.dsl/delegation-reassignment-stale-vote-source.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegation-reassignment-stale-vote-source.yaml
Source: solodit-8730-c4-golom
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegationReassignmentStaleVoteSource(AbstractDetector):
    ARGUMENT = "delegation-reassignment-stale-vote-source"
    HELP = "Redelegation appends the vote source to the new delegate path without clearing the old delegate path first, so one token or balance can be counted multiple times."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegation-reassignment-stale-vote-source.yaml"
    WIKI_TITLE = "Redelegation leaves stale vote source on the old delegate"
    WIKI_DESCRIPTION = "Delegation systems that move a token, NFT, or voting unit from one delegate to another must remove the old delegate relationship before appending the same source to the new delegate's list or checkpoint. If the old delegate entry is left live, subsequent vote accounting includes the same source in both places and the holder can multiply governance weight by repeatedly redelegating."
    WIKI_EXPLOIT_SCENARIO = "A governance token stores `delegatedTokenIds[toDelegate]` and computes voting power from that list. Alice owns token 1 with 1000 votes and calls `delegate(1, 2)`, then `delegate(1, 3)`, then `delegate(1, 4)`. Each call appends token 1 to the new delegate's list but never removes it from the old one. When the DAO tallies votes, delegates 2, 3, and 4 each still inherit token 1, so Alice reuses the s"
    WIKI_RECOMMENDATION = "Before writing the new delegation edge, clear the old edge in the same transaction. Common safe shapes are `removeDelegation(oldDelegate, tokenId)` before `push`, swap-and-pop removal from the old delegate's array, or a canonical `_moveDelegateVotes(oldDelegate, newDelegate, amount)` helper that deb"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(delegate|delegation|delegatedTokenIds|delegatedVotes|checkpoints)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|redelegate|setDelegate|changeDelegate|updateDelegation|moveDelegation)$'}, {'function.source_matches_regex': '(?i)(oldDelegate|currentDelegate|previousDelegate|delegatedTo)'}, {'function.source_matches_regex': '(?i)(delegatedTokenIds\\s*\\[\\s*\\w+\\s*\\]\\s*\\.push\\s*\\(\\s*\\w+\\s*\\)|\\.delegatedTokenIds\\s*\\.push\\s*\\(\\s*\\w+\\s*\\))'}, {'function.not_source_matches_regex': '(?i)(removeDelegation|_removeDelegation|detachDelegate|clearOldDelegate|_moveDelegateVotes|swapAndPop|swap\\s*and\\s*pop|deleteOldDelegate|removeFromOldDelegate)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" - delegation-reassignment-stale-vote-source: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
