"""
permissionless-claim-parameter-setter — generated from reference/patterns.dsl/permissionless-claim-parameter-setter.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py permissionless-claim-parameter-setter.yaml
Source: DeFiHackLabs/ABCCApp (2025-08, 10K BUSD) — addFixedDay(uint256 target) was callable by anyone and controlled the amount claimDDDD() later minted to the caller; attacker set target = 1e9 and minted windfall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PermissionlessClaimParameterSetter(AbstractDetector):
    ARGUMENT = "permissionless-claim-parameter-setter"
    HELP = "A claim / reward parameter (per-user target, rate, or allocation) is mutated by an unrestricted setter and later consumed by mint/claim. Attackers oversize their target and mint a windfall."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/permissionless-claim-parameter-setter.yaml"
    WIKI_TITLE = "Permissionless claim-parameter setter drives oversized mint"
    WIKI_DESCRIPTION = "The contract has a setter (addFixedDay / setTarget / setRate / configureReward) that writes a storage slot later read by a claim / mint / redeem function. The setter is missing both an onlyOwner / onlyRole modifier AND any bound check (`require(target <= MAX)`). A caller can invoke the setter with an arbitrarily large value and then trigger the consumer, which mints proportionally to the attacker-"
    WIKI_EXPLOIT_SCENARIO = "ABCCApp (2025-08, 10K BUSD). The contract exposed `addFixedDay(uint256 target) external` with no modifier. Attacker flash-loaned BUSD, called deposit(125, address(0)), then addFixedDay(1_000_000_000) to set their personal target to 1e9, then claimDDDD() which minted DDDD tokens in proportion to the target. Attacker swapped the DDDD out via PancakeSwap and repaid the flash loan with ~10K BUSD profi"
    WIKI_RECOMMENDATION = "Gate the parameter setter with onlyOwner or onlyRole(KEEPER_ROLE). If per-user targets are legitimate, bound them: `require(target <= maxTargetForUser(msg.sender))`. If the setter must remain permissionless, decouple it from the mint: the setter only records a declared intent, and a second admin-sig"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'target|rate|rewardPerUser|claimAmount|fixedDay|cap|allocation|reward'}, {'contract.has_function_matching': 'claim|redeem|mint|harvest|withdraw'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(add|set|update|configure|register|declare)(FixedDay|Target|Rate|Claim|Reward|Allocation|Cap|Amount|DailyReward|Accrual)$|^setMyClaim|^setUserTarget'}, {'function.writes_storage_matching': 'target|rate|rewardPerUser|claimAmount|fixedDay|allocation|reward|amount'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyGovernance', 'onlyKeeper', 'onlyConfigurator', 'onlyOperator'], 'negate': True}}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(target|amount|rate)\\s*<=|require\\s*\\(\\s*msg\\.sender\\s*==\\s*(owner|admin|user|operator)|MAX_TARGET|maxTarget|MAX_RATE|cap\\s*\\[|bounds\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — permissionless-claim-parameter-setter: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
