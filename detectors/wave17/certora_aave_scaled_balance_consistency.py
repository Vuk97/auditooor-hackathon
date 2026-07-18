"""
certora-aave-scaled-balance-consistency — generated from reference/patterns.dsl/certora-aave-scaled-balance-consistency.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-aave-scaled-balance-consistency.yaml
Source: certora-aave-v3-core/aToken/scaledBalanceConsistency
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAaveScaledBalanceConsistency(AbstractDetector):
    ARGUMENT = "certora-aave-scaled-balance-consistency"
    HELP = "Mutation of a rebasing balance field without using the scaled index path — `scaledTotalSupply * index == totalSupply` invariant breaks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-aave-scaled-balance-consistency.yaml"
    WIKI_TITLE = "aToken / scaled-balance mutation skips index, breaks Aave certora invariant"
    WIKI_DESCRIPTION = "Aave's Certora spec enforces that at any point the displayed balance equals the scaled (index-deflated) amount multiplied by the current liquidity / variable-borrow index (`rayMul(scaled, index) == balance`). A mutator that writes raw `totalSupply`/`_balances` without first converting through `rayDiv(amount, index)` or without also updating `scaledTotalSupply` causes the two views to drift. After "
    WIKI_EXPLOIT_SCENARIO = "A patch adds `adminCredit(user, amount)` that does `_balances[user] += amount; totalSupply += amount;` (treating the aToken as a vanilla ERC20). Next accrual multiplies the stale `scaledTotalSupply` by the new index, yielding a totalSupply lower than the sum of displayed balances. Users' withdrawals of the accrued interest partially fail; a clever user front-runs the accrual with a tiny transfer t"
    WIKI_RECOMMENDATION = "All balance writers on index-scaled tokens must go through the scaled path: compute `scaledDelta = amount.rayDiv(index)`, write the scaled balance, and let `balanceOf()` reconstruct. Reproduce Certora's `scaledBalanceConsistency` as a Foundry invariant pinning both quantities after each operation."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(aToken|AToken|scaledBalance|scaledTotalSupply|IncentivizedERC20|reserveNormalizedIncome|rayMul|rayDiv|liquidityIndex|variableBorrowIndex)'}, {'contract.has_state_var_matching': '(?i)(scaled|_scaled|liquidityIndex|variableBorrowIndex|reserveNormalizedIncome)'}, {'contract.has_state_var_matching': '(?i)(totalSupply|_totalSupply|scaledTotalSupply)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(totalSupply|_totalSupply|_balances|balances)'}, {'function.body_not_contains_regex': '(?i)(scaledTotalSupply|scaledBalance|_scaled|liquidityIndex|index\\s*\\*|/\\s*index|rayDiv|rayMul)'}, {'function.name_matches': '(?i)^(mint|burn|_mint|_burn|transfer|_transfer|transferFrom|_transferFrom|repay|_repay|liquidationCall|seize|_seize|redeem|_redeem|credit|_credit|debit|_debit)\\w*$'}, {'function.not_source_matches_regex': '(?i)(super\\._update|super\\._mint|super\\._burn|super\\._transfer|ERC20Upgradeable|VaultAccounting\\.\\w+|IERC20\\.transfer)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-aave-scaled-balance-consistency: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
