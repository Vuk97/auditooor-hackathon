"""
integration-address-rotation-no-reapproval — generated from reference/patterns.dsl/integration-address-rotation-no-reapproval.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py integration-address-rotation-no-reapproval.yaml
Source: code4arena-2025-08-morpheus-M-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntegrationAddressRotationNoReapproval(AbstractDetector):
    ARGUMENT = "integration-address-rotation-no-reapproval"
    HELP = "Admin setter rotates an external integration address (pool / router / strategy) but does not revoke the old ERC20 approval or grant a fresh one — leaves funds stranded or leaves dormant allowance on the decommissioned contract."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/integration-address-rotation-no-reapproval.yaml"
    WIKI_TITLE = "Integration-address rotation without approval migration"
    WIKI_DESCRIPTION = "A privileged setter (setAavePool, setRouter, migrateStrategy, etc.) mutates a storage field that holds the address of an external protocol the contract deposits into. Deposits rely on a pre-granted ERC20 allowance from this contract to the stored pool. When the setter writes the new address WITHOUT (a) revoking the allowance held by the old pool and (b) granting fresh allowance to the new pool, tw"
    WIKI_EXPLOIT_SCENARIO = "Protocol originally integrates with Aave V3 (pool address POOL_A). Admin grants `WETH.approve(POOL_A, type(uint256).max)` via initialize(). Aave V3 is later deprecated and admin calls `setAavePool(POOL_B)`. The setter writes `aavePool = POOL_B` but touches no allowances. (1) Every user deposit now reverts because POOL_B has zero allowance. (2) POOL_A still holds unbounded allowance; if an attacker"
    WIKI_RECOMMENDATION = "In every integration-address rotation setter, explicitly revoke the old allowance and grant the new one atomically: `IERC20(token).forceApprove(oldPool, 0); IERC20(token).forceApprove(newPool, type(uint256).max);`. Emit an event per approval change. If the contract uses `isAdded` style boolean flags"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pool|router|strategy|vault|adapter|integration|aavePool|lendingPool|morphoBlue'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|switch|change|rotate|migrate)(Aave)?(Pool|Router|Strategy|LendingPool|Vault|Adapter|Integration)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'onlyGovernor', 'onlyRoles'], 'negate': False}}, {'function.writes_storage_matching': 'pool|router|strategy|vault|adapter|integration|aavePool|lendingPool'}, {'function.body_not_contains_regex': '\\.approve\\s*\\(|forceApprove\\s*\\(|safeApprove\\s*\\(|safeIncreaseAllowance|safeDecreaseAllowance|_approveToken|_setApproval'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — integration-address-rotation-no-reapproval: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
