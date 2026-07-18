"""
protocol-doesn-t-properly-handle-aave-pool-changes — generated from reference/patterns.dsl/protocol-doesn-t-properly-handle-aave-pool-changes.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py protocol-doesn-t-properly-handle-aave-pool-changes.yaml
Source: code4arena-2025-08-morpheus-M-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ProtocolDoesnTProperlyHandleAavePoolChanges(AbstractDetector):
    ARGUMENT = "protocol-doesn-t-properly-handle-aave-pool-changes"
    HELP = "A privileged Aave pool setter rotates the pool address without migrating ERC20 allowances."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/protocol-doesn-t-properly-handle-aave-pool-changes.yaml"
    WIKI_TITLE = "Protocol does not properly handle Aave Pool changes"
    WIKI_DESCRIPTION = "A privileged setter updates an Aave pool address used as an ERC20 approval spender, but does not revoke allowance from the old pool or approve the new pool in the same rotation path. In the Morpheus case, approval setup was gated elsewhere by an isDepositTokenAdded-style flag, so merely updating the stored pool address left deposits pointed at a pool with no allowance while the old pool retained s"
    WIKI_EXPLOIT_SCENARIO = "The protocol initially approves POOL_A to pull deposit tokens. The owner later calls setAavePool(POOL_B), which only writes storage. Future deposits through POOL_B lack allowance, while POOL_A keeps its stale allowance."
    WIKI_RECOMMENDATION = "When rotating the pool, atomically revoke allowance from the old pool and grant allowance to the new pool, or move approval setup into a helper that is always called by the setter."

    _PRECONDITIONS = [{'contract.has_state_var_matching': 'aavePool|lendingPool'}, {'contract.source_matches_regex': '(?i)aave|IPool|lendingPool'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(set|update|change|switch|rotate)(Aave|Lending)?Pool$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'onlyGovernor', 'onlyRoles'], 'negate': False}}, {'function.writes_storage_matching': 'aavePool|lendingPool|pool'}, {'function.body_not_contains_regex': '\\.approve\\s*\\(|forceApprove\\s*\\(|safeApprove\\s*\\(|safeIncreaseAllowance|safeDecreaseAllowance|_approveToken|_setApproval'}]

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
                info = [f, f" — protocol-doesn-t-properly-handle-aave-pool-changes: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
