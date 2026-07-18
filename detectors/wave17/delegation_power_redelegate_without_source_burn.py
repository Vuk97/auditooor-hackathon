"""
delegation-power-redelegate-without-source-burn - generated from reference/patterns.dsl/delegation-power-redelegate-without-source-burn.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegation-power-redelegate-without-source-burn.yaml
Source: rwrq-delegation-power-inflation-18fb03d27ef7
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegationPowerRedelegateWithoutSourceBurn(AbstractDetector):
    ARGUMENT = "delegation-power-redelegate-without-source-burn"
    HELP = "NOT_SUBMIT_READY fixture-smoke detector: redelegation credits a destination power ledger without burning or debiting the old source ledger."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegation-power-redelegate-without-source-burn.yaml"
    WIKI_TITLE = "Delegation redelegation without source burn"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A delegation or redelegation function that credits a destination delegate power ledger from a user's balance, stake, shares, or voting units must also burn or debit the old source delegate bucket. If it only credits the destination, the same units can remain counted in the source and destination ledgers."
    WIKI_EXPLOIT_SCENARIO = "A holder delegates voting units to one delegate, then calls a redelegation path to point the same units at a second delegate. The destination delegate receives credited power, but the prior delegate/source bucket is never burned or debited, inflating total delegation power."
    WIKI_RECOMMENDATION = "Read the current delegate/source, debit or burn that bucket before crediting the destination bucket, or route the update through a single move-delegates helper that performs both sides of the accounting update."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(delegate|delegation|redelegat|delegateOf|delegatedTo|delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)'}, {'contract.source_matches_regex': '(?i)(balanceOf|balances|stake|stakes|amount|weight|votes|power|shares|units|_getVotingUnits|getVotes)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|redelegate|setDelegate|changeDelegate|updateDelegate|updateDelegation|assignDelegate|reassignDelegate|moveDelegation)$'}, {'function.body_contains_regex': '(?is)(delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)\\s*\\[[^\\]]+\\]\\s*(\\+=|=\\s*[^;\\n]+\\+)'}, {'function.body_contains_regex': '(?is)(balanceOf\\s*\\[|balances\\s*\\[|stake[s]?\\s*\\[|amount|weight|votes|power|shares|units|_getVotingUnits\\s*\\(|getVotes\\s*\\()'}, {'function.body_not_contains_regex': '(?is)(delegationPower|delegatePower|delegatedPower|votingPower|votePower|delegateVotes|delegatedVotes|votesByDelegate|votePowerByDelegate|delegateWeight|delegatedWeight|validatorPower)\\s*\\[[^\\]]+\\]\\s*(-=|=\\s*[^;\\n]+-|=\\s*0)'}, {'function.body_not_contains_regex': '(?is)(_moveDelegates|_moveDelegateVotes|_moveVotingPower|_transferVotingUnits|moveDelegateVotes|moveDelegationPower|burnSourcePower|burnOldSource|debitOldDelegate|debitDelegate|subtractOldDelegate|removeDelegation|_removeDelegation|clearOldDelegate|clearDelegation|detachDelegate|removeFromOldDelegate)\\s*\\('}, {'function.not_source_matches_regex': '(?i)(selfDelegated|selfDelegate)'}, {'function.not_source_matches_regex': '(?i)\\.push\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}]

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
                info = [f, f" - delegation-power-redelegate-without-source-burn: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
