"""
vote-power-reassignment-missing-debit

Fixture-smoke-only detector for vote-double-count reassignment shapes where
new vote power is credited before the prior source is debited.
NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotePowerReassignmentMissingDebit(AbstractDetector):
    ARGUMENT = "vote-power-reassignment-missing-debit"
    HELP = "Vote power reassignment credits the new source without debiting the old source"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Vote power reassignment misses the old source debit"
    WIKI_DESCRIPTION = (
        "A vote power reassignment reads the old delegate or vote source, "
        "writes a new source, and credits the new source ledger without first "
        "debiting the old source ledger. The same voting units can remain live "
        "under the previous source and also be counted under the new source."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A voter with vote power assigned to source A is reassigned to source B. "
        "The contract credits source B but never subtracts from source A, so a "
        "tally that reads both ledgers can count one deposit twice."
    )
    WIKI_RECOMMENDATION = (
        "Debit the old source before crediting the new source, or route all "
        "reassignment through a single move-vote-power helper."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                r"(?i)(voteSourceOf|delegateOf|delegates|voteDelegate)"
            )
        },
        {
            "contract.source_matches_regex": (
                r"(?i)(votePowerBySource|delegatedVotes|delegateVotes|"
                r"votingPower|votePower)"
            )
        },
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                r"(?i)^(delegate|setDelegate|updateDelegate|changeDelegate|"
                r"reassignVoteSource|setVoteSource|moveVoteSource)$"
            )
        },
        {
            "function.body_contains_regex": (
                r"(?i)(?:address|uint256)\s+"
                r"(oldSource|oldDelegate|previousSource|previousDelegate|"
                r"currentSource|currentDelegate)\s*=\s*"
                r"(voteSourceOf|delegateOf|delegates|voteDelegate)\s*\["
            )
        },
        {
            "function.body_contains_regex": (
                r"(?i)(voteSourceOf|delegateOf|delegates|voteDelegate)"
                r"\s*\[[^\]]+\]\s*=\s*"
                r"(newSource|newDelegate|delegatee|to|representative)"
            )
        },
        {
            "function.body_contains_regex": (
                r"(?i)(votePowerBySource|delegatedVotes|delegateVotes|"
                r"votingPower|votePower)\s*\[\s*"
                r"(newSource|newDelegate|delegatee|to|representative)\s*\]"
                r"\s*\+="
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?i)(votePowerBySource|delegatedVotes|delegateVotes|"
                r"votingPower|votePower)\s*\[\s*"
                r"(oldSource|oldDelegate|previousSource|previousDelegate|"
                r"currentSource|currentDelegate)\s*\]\s*-="
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?i)(_moveVotePower|_moveDelegateVotes|_moveDelegates|"
                r"_debitOldSource|_debitDelegate|_removeDelegateVotes|"
                r"removeDelegation|clearOldDelegate|clearOldVoteSource|"
                r"debitVoteSource)\s*\("
            )
        },
        {"function.not_in_skip_list": True},
        {"function.not_slither_synthetic": True},
        {"function.not_source_matches_regex": r"(?i)\b(mock|test|fixture)\b"},
    ]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

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
                        " vote-power-reassignment-missing-debit: reassignment "
                        "credits the new vote source without debiting the old "
                        "source. See WIKI for details."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
