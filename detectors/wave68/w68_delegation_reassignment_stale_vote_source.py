"""
w68-delegation-reassignment-stale-vote-source - narrow wave68 sibling of the
confirmed corpus pattern `delegation-reassignment-stale-vote-source`.
Derived from reference/patterns.dsl/delegation-reassignment-stale-vote-source.yaml
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68DelegationReassignmentStaleVoteSource(AbstractDetector):
    ARGUMENT = "w68-delegation-reassignment-stale-vote-source"
    HELP = (
        "Redelegation or repeat delegation credits a new delegate path "
        "without clearing the old delegate path first."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "delegation-reassignment-stale-vote-source.yaml"
    )
    WIKI_TITLE = "Redelegation leaves stale vote source on the old delegate"
    WIKI_DESCRIPTION = (
        "Delegation systems that move a token, NFT, or voting unit from one "
        "delegate to another must remove the old delegate relationship before "
        "appending the same source to the new delegate's list or checkpoint, "
        "or must debit the old delegate's power before crediting the new one. "
        "If the old delegate entry is left live, or the old delegate is never "
        "debited at all, later vote accounting counts the same source in both "
        "places."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A governance token stores delegatedTokenIds[toDelegate] and computes "
        "voting power from that list. Alice redelegates the same token from "
        "delegate 2 to delegate 3 to delegate 4. Each call appends token 1 to "
        "the new delegate's list but never removes it from the old one, so the "
        "same voting source is reused multiple times."
    )
    WIKI_RECOMMENDATION = (
        "Before writing the new delegation edge, clear the old edge in the "
        "same transaction. Use removeDelegation(oldDelegate, tokenId), "
        "swap-and-pop removal, or a canonical _moveDelegateVotes helper that "
        "debits before crediting. If the protocol tracks only aggregate power, "
        "store the prior delegate and subtract from it before adding to the "
        "new delegate."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": "(?i)(delegate|delegation|delegatedTokenIds|delegatedVotes|checkpoints|voteCheckpoints|delegationPower|votingPower|delegateOf)"
        }
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": "(?i)^(delegate|redelegate|setDelegate|changeDelegate|updateDelegation|moveDelegation)$"
        },
        {
            "function.body_contains_regex": "(?i)(delegatedTokenIds\\s*\\[\\s*\\w+\\s*\\]\\s*\\.push\\s*\\(\\s*\\w+\\s*\\)|\\.delegatedTokenIds\\s*\\.push\\s*\\(\\s*\\w+\\s*\\)|(?:delegationPower|votingPower|delegateVotes|delegatedPower)\\s*\\[[^\\]]+\\]\\s*\\+=)"
        },
        {
            "function.body_not_contains_regex": "(?i)(removeDelegation|_removeDelegation|detachDelegate|clearOldDelegate|_moveDelegateVotes|swapAndPop|swap\\s*and\\s*pop|deleteOldDelegate|removeFromOldDelegate|(?:delegationPower|votingPower|delegateVotes|delegatedPower)\\s*\\[[^\\]]+\\]\\s*-=)"
        },
        {"function.not_in_skip_list": True},
        {"function.not_leaf_helper": True},
        {"function.not_source_matches_regex": "(?i)\\b(mock|test|fixture)\\b"},
    ]

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
                info = [
                    f,
                    " - w68-delegation-reassignment-stale-vote-source: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
