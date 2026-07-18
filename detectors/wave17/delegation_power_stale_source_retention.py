"""
delegation-power-stale-source-retention

Fixture-smoke detector for the delegation-power-inflation sibling gap where a
delegate update credits the new delegate from the delegator's balance while the
old vote source is never debited. This is intentionally distinct from the
self-delegation reset detector, which handles selfDelegated state and voting
receipts.
NOT_SUBMIT_READY.
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegationPowerStaleSourceRetention(AbstractDetector):
    ARGUMENT = "delegation-power-stale-source-retention"
    HELP = "Delegation credits a new vote-power source without debiting the old source"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor"
    WIKI_TITLE = "Delegation power source retained after redelegation"
    WIKI_DESCRIPTION = (
        "Delegation accounting must move voting units from the previous "
        "delegate to the new delegate. A delegate update that only credits "
        "the new delegate retains the same units on the old source and "
        "inflates total delegated power."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A holder delegates voting units, then redelegates to another address. "
        "The new delegate receives balance-backed voting units, but the old "
        "delegate ledger is never reduced, so repeated delegation mints "
        "governance weight in the accounting layer."
    )
    WIKI_RECOMMENDATION = (
        "Read the current delegate and debit that delegate before crediting "
        "the new one, or route every update through a move-delegates helper."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                r"(?i)(delegationPower|delegatedVotes|delegateVotes|"
                r"votePower|votingPower)"
            )
        },
        {"contract.source_matches_regex": r"(?i)(balanceOf|votingUnits|getVotes)"},
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                r"(?i)^(delegate|redelegate|setDelegate|changeDelegate|"
                r"updateDelegate|updateDelegation)$"
            )
        },
        {
            "function.body_contains_regex": (
                r"(?is)(delegationPower|delegatedVotes|delegateVotes|"
                r"votePower|votingPower)\s*\[[^\]]+\]\s*\+="
            )
        },
        {
            "function.body_contains_regex": (
                r"(?is)(balanceOf\s*\[\s*msg\.sender\s*\]|"
                r"votingUnits\s*\[\s*msg\.sender\s*\]|"
                r"_getVotingUnits\s*\(|getVotes\s*\()"
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?is)(delegationPower|delegatedVotes|delegateVotes|"
                r"votePower|votingPower)\s*\[[^\]]+\]\s*-="
            )
        },
        {
            "function.body_not_contains_regex": (
                r"(?is)(_moveDelegates|_moveVotingPower|_transferVotingUnits|"
                r"_debitDelegate|_removeDelegateVotes|moveDelegateVotes)\s*\("
            )
        },
        {"function.not_source_matches_regex": r"(?i)(selfDelegated|selfDelegate)"},
        {"function.not_source_matches_regex": r"(?i)\.push\s*\("},
        {"function.not_in_skip_list": True},
        {"function.not_slither_synthetic": True},
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
                        " - delegation-power-stale-source-retention: new "
                        "delegate is credited while the old vote-power source "
                        "is not debited. See WIKI for details."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
