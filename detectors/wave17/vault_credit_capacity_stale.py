"""
vault-credit-capacity-stale - generated from reference/patterns.dsl/vault-credit-capacity-stale.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-credit-capacity-stale.yaml
Source: solodit/C0334
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultCreditCapacityStale(AbstractDetector):
    ARGUMENT = "vault-credit-capacity-stale"
    HELP = "Vault branch function changes credit-capacity-affecting state (credit/capacity/weight/collateral/utilization/debt) without calling the contract's updateCreditCapacity / recalcCredit / syncCapacity helper first; downstream readers consume a stale value, DOSing deposits, exits, or liquidation flows."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-credit-capacity-stale.yaml"
    WIKI_TITLE = "Vault credit capacity not refreshed on capacity-mutating branch entry points"
    WIKI_DESCRIPTION = "Vault-router contracts typically expose an accrual helper (updateCreditCapacity / recalculateCredit / syncCapacity / _updateCapacity / refreshCapacity / checkpointCapacity) that materializes the current credit / debt / weight-weighted capacity of each market connected to the vault. Branch-level entry points - deposit, withdraw, transfer, rebalance, setWeight, liquidation exits, collateral swaps - "
    WIKI_EXPLOIT_SCENARIO = "(1) A user calls deposit() or withdraw() on the vault branch. The branch mutates collateral or utilization and returns, but never calls updateCreditCapacity. (2) A later read of `current + deposit <= cap`, `maxWithdraw`, or an exit path consumes the stale totalCreditCapacity and either permits an over-cap action or reverts a legitimate one. (3) Separately, after a liquidation rebalances the market"
    WIKI_RECOMMENDATION = "At the top of every branch entry point that mutates credit / capacity / market-weight / collateral / utilization / debt state, call the accrual helper (updateCreditCapacity / recalcCredit / syncCapacity / refreshCapacity / checkpointCapacity) for every affected market BEFORE writing. If the helper i"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'credit|capacity|marketWeight|utilization|collateral|debt'}, {'contract.has_function_matching': 'updateCredit|recalcCredit|syncCapacity|_updateCapacity|refreshCapacity|refreshCredit|checkpointCapacity'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'deposit|withdraw|transfer|rebalance|setWeight|_swapCollateral|liquidat|redeem|exit|close'}, {'function.writes_storage_matching': 'credit|capacity|weight|collateral|utilization|debt'}, {'function.calls_function_matching': {'regex': 'updateCredit|_updateCapacity|recalc|sync|refreshCapacity|refreshCredit|checkpointCapacity', 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - vault-credit-capacity-stale: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
