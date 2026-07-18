"""
zero-amount-deposit-accrues-rewards — generated from reference/patterns.dsl/zero-amount-deposit-accrues-rewards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py zero-amount-deposit-accrues-rewards.yaml
Source: DeFiHackLabs/AaveBoost (2025-06, $14.8K) — proxyDeposit(proxy, attacker, amount=0) was called 163 times, each no-op deposit still walked the reward-accrual loop and credited shares
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ZeroAmountDepositAccruesRewards(AbstractDetector):
    ARGUMENT = "zero-amount-deposit-accrues-rewards"
    HELP = "Deposit / stake / mint function mutates reward or share storage but does not reject amount == 0. Attackers spam zero-amount calls to farm accrual side effects (boost, rebase, index credit)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/zero-amount-deposit-accrues-rewards.yaml"
    WIKI_TITLE = "Deposit with amount=0 accrues rewards or shares"
    WIKI_DESCRIPTION = "A deposit / stake / proxyDeposit / supply entry-point walks its reward-index update and share-minting path unconditionally. When called with amount == 0 it still executes any side-effect bookkeeping (e.g., crediting boost points, claiming proxy rewards, updating a per-user index to the current global index). If the side effect is monotonic (e.g., a boost counter that grows with call count, or a re"
    WIKI_EXPLOIT_SCENARIO = "AaveBoost (2025-06, $14.8K). The attacker called proxyDeposit(InitializableAdminUpgradeabilityProxy, attackContract, 0) in a loop of 163 iterations. Each call hit the reward-accrual path and credited the proxy-token balance, but the amount=0 guard was absent. After the loop the attacker withdrew from the AavePool into the wrapper and transferred the inflated balance out."
    WIKI_RECOMMENDATION = "Add `require(amount > 0, 'zero amount')` (or a revert NonZeroAmount()) as the first statement of every deposit / stake / supply / mint / proxyDeposit entry-point. For rebase-style accrual updates that must run regardless of amount, split the logic: a permissioned `accrue()` that runs the update, and"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'balance|shares|rewardIndex|accRewardPerShare|boost'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|proxyDeposit|stake|supply|mint|increaseStake|boost|accrue|provide)$|^(deposit|proxyDeposit|stake|supply|mint)[A-Z]'}, {'function.has_param_name_matching': 'amount|value|assets|shares|qty'}, {'function.writes_storage_matching': 'balance|shares|reward|boost|index|accrued'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(amount|value|assets|shares|qty)\\s*(>\\s*0|!=\\s*0)|if\\s*\\(\\s*(amount|value|assets|shares|qty)\\s*==\\s*0\\s*\\)\\s*(return|revert)|ZeroAmount|_requireAmountNonZero'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — zero-amount-deposit-accrues-rewards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
