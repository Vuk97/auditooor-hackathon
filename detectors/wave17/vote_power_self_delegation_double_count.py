"""
vote-power-self-delegation-double-count

Fixture-smoke-only detector for confirmed vote-double-count memories:
legacy:solodit_8730_h04-old-delegatee-not-deleted-when-deleg:749d1807ff97
and Solodit 33575 self-delegation reset state inconsistency.
NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from _predicate_engine import eval_function_match, eval_preconditions

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotePowerSelfDelegationDoubleCount(AbstractDetector):
    ARGUMENT = "vote-power-self-delegation-double-count"
    HELP = "Self-delegated voting power can be retained on the old delegate while credited to a new delegate"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Stale self-delegate source double-counts voting power"
    WIKI_DESCRIPTION = (
        "A delegation update reads the current delegate, writes a new delegate, "
        "and credits the new delegate's vote ledger without debiting the old "
        "delegate. If the old delegate was the account's self-delegation, the "
        "same voting units remain usable by the old source and are also usable "
        "by the new delegate."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A voter self-delegates, then changes delegation to another address. "
        "The new delegate receives the voter's voting units while the old "
        "self-delegate checkpoint remains live, so two voting paths consume "
        "one unit of voting power."
    )
    WIKI_RECOMMENDATION = (
        "Debit the old delegate before crediting the new delegate, or use a "
        "single move-delegates helper that handles self-delegation explicitly."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                r"(?i)(selfDelegated|selfDelegate|delegateOf|voteDelegate|delegates)"
            )
        },
        {
            "contract.source_matches_regex": (
                r"(?i)(delegatedVotes|delegateVotes|votingPower|votePower)"
            )
        },
        {"contract.has_function_matching": r"(?i)(castVote|vote|tally|quorum|getVotes|voteWeight)"},
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {"function.name_matches": r"(?i)^(delegate|setDelegate|updateDelegate|changeDelegate|delegateFor|setVoteDelegate)$"},
        {
            "function.body_contains_regex": (
                r"(?i)address\s+(oldDelegate|previousDelegate|currentDelegate)\s*=\s*"
                r"(delegateOf|delegates|voteDelegate)\s*\["
            )
        },
        {
            "function.body_contains_regex": (
                r"(?i)(delegateOf|delegates|voteDelegate)\s*\[[^\]]+\]\s*=\s*"
                r"(newDelegate|delegatee|to)"
            )
        },
        {
            "function.body_contains_regex": (
                r"(?i)(delegatedVotes|delegateVotes|votingPower|votePower)\s*\[\s*"
                r"(newDelegate|delegatee|to)\s*\]\s*\+="
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?i)(delegatedVotes|delegateVotes|votingPower|votePower)\s*\[\s*"
                r"(oldDelegate|previousDelegate|currentDelegate)\s*\]\s*-="
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?i)(_moveDelegates|_moveVotingPower|_transferVotingUnits|"
                r"_debitDelegate|_removeDelegateVotes)\s*\("
            )
        },
        {"function.not_in_skip_list": True},
        {"function.not_source_matches_regex": r"(?i)\b(mock|test|fixture)\b"},
    ]

    _INCLUDE_LEAF_HELPERS = False

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    (
                        " vote-power-self-delegation-double-count: stale old "
                        "delegate source is credited through a second vote path. "
                        "See WIKI for details."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
