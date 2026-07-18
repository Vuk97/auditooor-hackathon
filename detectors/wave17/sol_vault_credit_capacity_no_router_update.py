"""
sol-vault-credit-capacity-no-router-update — generated from reference/patterns.dsl/sol-vault-credit-capacity-no-router-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-vault-credit-capacity-no-router-update.yaml
Source: solodit-cluster-C0352
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolVaultCreditCapacityNoRouterUpdate(AbstractDetector):
    ARGUMENT = "sol-vault-credit-capacity-no-router-update"
    HELP = "Vault deposit forgets to notify credit-branch — capacity calculation stale, downstream operations DOS."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-vault-credit-capacity-no-router-update.yaml"
    WIKI_TITLE = "Vault deposit leaves credit capacity stale"
    WIKI_DESCRIPTION = "Split-branch architectures (e.g. Zaros vault router vs credit-delegation branch) must keep a cross-branch invariant: every asset mutation updates any dependent capacity. Missing the update causes the credit branch to revert in `depositCreditForMarket` because it sees the old capacity."
    WIKI_EXPLOIT_SCENARIO = "Zaros C0352: `VaultRouterBranch.deposit` increased vault balances but did not call `_updateCreditCapacity()`. Subsequent `CreditDelegationBranch.depositCreditForMarket` reverted because capacity was zero; users who deposited had no path to enter credit delegation until an admin manually poked."
    WIKI_RECOMMENDATION = "Emit a cross-branch hook from every deposit/withdraw: `CreditDelegationBranch.recalcCapacity()`. Or centralize asset state in a single ledger that both branches read."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'VaultRouter|CreditDelegation|VaultBranch|CreditBranch|depositCredit'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|mint|addCollateral)$'}, {'function.body_contains_regex': 'vault|_vaultDeposit|totalDeposited|assetsUnderManagement'}, {'function.body_not_contains_regex': '_updateCreditCapacity|recalcCreditCapacity|notifyCreditBranch|CreditDelegation.*update'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-vault-credit-capacity-no-router-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
