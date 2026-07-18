"""
rollup-requiredStake-stale-based-on-parent-not-current — generated from reference/patterns.dsl/rollup-requiredStake-stale-based-on-parent-not-current.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rollup-requiredStake-stale-based-on-parent-not-current.yaml
Source: auditooor-R75-c4-mined-2024-05-arbitrum-foundation-46
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RollupRequiredstakeStaleBasedOnParentNotCurrent(AbstractDetector):
    ARGUMENT = "rollup-requiredStake-stale-based-on-parent-not-current"
    HELP = "`stakeOnNewAssertion` enforces `amountStaked(msg.sender) >= assertion.beforeStateData.configData.requiredStake` — the requiredStake frozen at the PARENT assertion's creation. If the rollup's `baseStake` has since been increased (or the dynamic stake curve has scaled up due to liveness slowdown), use"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rollup-requiredStake-stale-based-on-parent-not-current.yaml"
    WIKI_TITLE = "newStakeOnNewAssertion uses parent-frozen requiredStake, allows under-collateralized assertions"
    WIKI_DESCRIPTION = "AssertionStakingPool.createAssertion → RollupUserLogic.newStakeOnNewAssertion → stakeOnNewAssertion. The stake check is `require(amountStaked(msg.sender) >= assertion.beforeStateData.configData.requiredStake)`. `configData` was set at the parent's creation time and includes the then-current baseStake. If the admin has since increased baseStake (via setBaseStake), or if the dynamic curve has scaled"
    WIKI_EXPLOIT_SCENARIO = "Admin sets baseStake = 100 ETH at genesis. Assertion chain: G (confirmed) -- A (pending, parent=G). A.configData.requiredStake = 100 (snapshotted at A's creation). Admin later calls setBaseStake(1000) because chain security requires stronger assertions. Honest validators staking 1000 ETH create assertion B under A. Attacker creates assertion C under A with `amountStaked = 100` (parent A's frozen v"
    WIKI_RECOMMENDATION = "In stakeOnNewAssertion, use both the parent's frozen value AND the current baseStake, taking the max: `require(amountStaked(msg.sender) >= max(assertion.beforeStateData.configData.requiredStake, currentBaseStake()), 'INSUFFICIENT_STAKE')`. This ensures that after a stake increase, all new assertions"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'RollupCore|RollupUserLogic|stakeOnNewAssertion|baseStake|configData'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '^(stakeOnNewAssertion|newStakeOnNewAssertion|_createNewAssertion)$'}, {'function.body_contains_regex': 'assertion\\.beforeStateData\\.configData\\.requiredStake|prev\\.configData\\.requiredStake'}, {'function.body_not_contains_regex': '(baseStake\\s*\\(\\s*\\)|currentBaseStake|block\\.timestamp\\s*-\\s*prevConfirmBlock|require\\s*\\(\\s*stake\\s*>=\\s*currentBaseStake|require\\s*\\(\\s*amountStaked\\s*>=\\s*baseStake\\(\\))'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rollup-requiredStake-stale-based-on-parent-not-current: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
