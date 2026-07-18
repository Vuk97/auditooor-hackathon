"""
rebase-token-snapshot-assumes-static-balance — generated from reference/patterns.dsl/rebase-token-snapshot-assumes-static-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebase-token-snapshot-assumes-static-balance.yaml
Source: auditooor/cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebaseTokenSnapshotAssumesStaticBalance(AbstractDetector):
    ARGUMENT = "rebase-token-snapshot-assumes-static-balance"
    HELP = "Contract snapshots rebase-token balanceOf into storage and later compares against current balanceOf. Rebase accrual corrupts the accounting."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebase-token-snapshot-assumes-static-balance.yaml"
    WIKI_TITLE = "Rebase token snapshot assumes static balance"
    WIKI_DESCRIPTION = "Rebase / interest-bearing tokens (stETH, aToken, cToken) have balances that change passively over time. Contracts that cache `token.balanceOf(user)` at deposit into a raw storage variable and later compare it against the current `balanceOf` observe drift from interest accrual. This corrupts withdrawal caps, share math, or reward accounting. The mitigation is to store the principal / scaled balance"
    WIKI_EXPLOIT_SCENARIO = "A vault deposits stETH and records `deposited[user] = stETH.balanceOf(address(this))`. Between deposit and the user's withdraw, stETH rebases upward so the contract's current balance exceeds the stored total. A subsequent user is allowed to withdraw more than their true share, or conversely (negative rebase) a user cannot withdraw because `deposited` exceeds the current balance. In lending integra"
    WIKI_RECOMMENDATION = "Track the principal / scaled balance. For aTokens use `scaledBalanceOf` and multiply by `getReserveNormalizedIncome` at read time. For cTokens store underlying via `balanceOfUnderlying` or track shares and `exchangeRateStored`. For stETH store shares via `sharesOf` and convert via `getPooledEthBySha"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'stETH|aToken|cToken|rebase|AToken|IAToken|CToken'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.writes_storage_matching': 'deposited|userBalance|balances|principal'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(stETH|aToken|cToken|_aToken|_stETH)\\.balanceOf\\s*\\(|IAToken\\(.*\\)\\.balanceOf|ICToken\\(.*\\)\\.balanceOf'}, {'function.body_not_contains_regex': 'scaledBalance|getScaledTotalSupply|getPrincipalDeposit|aaveScale|exchangeRate|_principal'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rebase-token-snapshot-assumes-static-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
