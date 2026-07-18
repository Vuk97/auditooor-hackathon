"""
delegation-power-credit-without-old-source-debit - generated from reference/patterns.dsl/delegation-power-credit-without-old-source-debit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegation-power-credit-without-old-source-debit.yaml
Source: w68-delegation-power-inflation-no-debit-scoreboard-lift
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegationPowerCreditWithoutOldSourceDebit(AbstractDetector):
    ARGUMENT = "delegation-power-credit-without-old-source-debit"
    HELP = "NOT_SUBMIT_READY fixture-smoke detector: delegation update credits a new delegate power ledger without debiting the old delegate/source ledger."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegation-power-credit-without-old-source-debit.yaml"
    WIKI_TITLE = "Delegation power credit without old-source debit"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A delegation update that credits a delegate power ledger from the delegator balance or voting units must also debit the prior delegate/source or route through a move-delegates helper. If it only credits the new delegate, repeated delegation can inflate total voting power."
    WIKI_EXPLOIT_SCENARIO = "A holder delegates voting units to one delegate, then delegates again to a new delegate. The new delegate receives credited voting power, but the old delegate ledger is never reduced, so the same balance can remain counted in more than one delegate power bucket."
    WIKI_RECOMMENDATION = "Read the current delegate/source, debit that old bucket before crediting the new bucket, or use a single move-delegates helper that performs both sides of the accounting update. Add a regression test that redelegating one voter never increases the sum of delegate power."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(delegate|delegation|delegateOf|delegatedTo|delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)'}, {'contract.source_matches_regex': '(?i)(balanceOf|balances|stake|stakes|amount|weight|votes|power|shares|units|_getVotingUnits|getVotes)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|redelegate|setDelegate|changeDelegate|updateDelegate|updateDelegation|assignDelegate|reassignDelegate|moveDelegation)$'}, {'function.body_contains_regex': '(?is)(delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)\\s*\\[[^\\]]+\\]\\s*(\\+=|=\\s*[^;\\n]+\\+)'}, {'function.body_contains_regex': '(?is)(balanceOf\\s*\\[|balances\\s*\\[|stake[s]?\\s*\\[|amount|weight|votes|power|shares|units|_getVotingUnits\\s*\\(|getVotes\\s*\\()'}, {'function.body_not_contains_regex': '(?is)(delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)\\s*\\[[^\\]]+\\]\\s*(-=|=\\s*[^;\\n]+-)'}, {'function.body_not_contains_regex': '(?is)(_moveDelegates|_moveDelegateVotes|_moveVotingPower|_transferVotingUnits|moveDelegateVotes|moveDelegationPower|debitOldDelegate|debitDelegate|subtractOldDelegate|removeDelegation|_removeDelegation|clearOldDelegate|clearDelegation|detachDelegate|removeFromOldDelegate)\\s*\\('}, {'function.not_source_matches_regex': '(?i)(selfDelegated|selfDelegate)'}, {'function.not_source_matches_regex': '(?i)\\.push\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

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
                info = [f, f" - delegation-power-credit-without-old-source-debit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
