"""
a-malicious-staker-can-force-validator-withdrawals-by-instantly- — generated from reference/patterns.dsl/a-malicious-staker-can-force-validator-withdrawals-by-instantly-.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-staker-can-force-validator-withdrawals-by-instantly-.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousStakerCanForceValidatorWithdrawalsByInstantly(AbstractDetector):
    ARGUMENT = "a-malicious-staker-can-force-validator-withdrawals-by-instantly-"
    HELP = "A malicious staker can force validator withdrawals by instantly staking and unstaking"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-staker-can-force-validator-withdrawals-by-instantly-.yaml"
    WIKI_TITLE = "A malicious staker can force validator withdrawals by instantly staking and unstaking"
    WIKI_DESCRIPTION = "**Description:** When a user unstakes via `CasimirManager::requestUnstake`, the number of required validator exits is calculated using the prevailing expected withdrawable balance as follows:\n\n```solidity\nfunction requestUnstake(uint256 amount) external nonReentrant {\n    // code ....\n    uint256 ex"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #35001: **Description:** When a user unstakes via `CasimirManager::requestUnstake`, the number of required validator exits is calculated using the prevailing expected withdrawable balance as follows:\n\n```soli"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(requestedWithdrawalBalance|requestedUnstakeBalance|requestedExits|prepoolBalance|exitedBalance|stakedPoolIds)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '.*(requestUnstake|requestWithdrawal).*'}, {'function.body_contains_regex': '(requestedWithdrawalBalance|requestedUnstakeBalance)\\s*\\+='}, {'function.body_contains_regex': '(coveredExitBalance|requestedExits)\\s*[^\\n;]*\\*\\s*(POOL_CAPACITY|32\\s*ether)'}, {'function.calls_function_matching': '.*(requestExits|exitValidators).*'}, {'function.body_not_contains_regex': '(availableWithdrawal|withdrawableBalance).{0,180}(coveredExitBalance|requestedExits|exitsRequired)|(coveredExitBalance|requestedExits|exitsRequired).{0,180}(availableWithdrawal|withdrawableBalance)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-malicious-staker-can-force-validator-withdrawals-by-instantly-: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
