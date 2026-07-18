"""
sharedstake-timelock-call-allows-approve-bypass — generated from reference/patterns.dsl/sharedstake-timelock-call-allows-approve-bypass.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sharedstake-timelock-call-allows-approve-bypass.yaml
Source: auditooor-R76-immunefi-sharedstake-$500k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SharedstakeTimelockCallAllowsApproveBypass(AbstractDetector):
    ARGUMENT = "sharedstake-timelock-call-allows-approve-bypass"
    HELP = "Timelock-protected call() relies on balance-before/after check to prevent outflow. But approve() doesn't change balance — beneficiary approves self, later transferFroms all tokens out, bypassing the timelock."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sharedstake-timelock-call-allows-approve-bypass.yaml"
    WIKI_TITLE = "Timelock arbitrary-call bypass via ERC-20 approve outside balance delta check"
    WIKI_DESCRIPTION = "A time-locked or guardian-gated contract holds tokens for a beneficiary and exposes an arbitrary `call(target, value, data)` behind a balance-delta check (`balance_after >= balance_before`). This pattern assumes token outflows happen via `transfer`/`transferFrom`. However, `approve(beneficiary, type(uint256).max)` doesn't move any tokens — so the balance check trivially passes. In a second, unprot"
    WIKI_EXPLOIT_SCENARIO = "SharedStake's SmartTimelock.call() let the beneficiary call any target with a balance-before/after guard. Attacker called it with target=tokenContract, data=approve(attacker, MAX). Balance unchanged → guard passed. Then tx2: transferFrom(timelock, attacker, all). ~$500k drained. Bounty/disclosure followup."
    WIKI_RECOMMENDATION = "Blacklist the `approve(address,uint256)` selector (0x095ea7b3) and `increaseAllowance` / `setApprovalForAll` (0xa22cb465 for ERC-721/1155) in the arbitrary-call path. Better: remove arbitrary-call entirely and whitelist specific functions. Snapshot ALL approvals before/after the call and require zer"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^call$|execute|executeTransaction|proxyCall|adminCall'}, {'function.has_modifier_regex': '(?i)onlyBeneficiary|onlyOwner|onlyExecutor'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '(?i)\\.call\\s*\\{[^}]*value\\s*:\\s*\\w+[^}]*\\}\\s*\\(\\s*data|\\.call\\s*\\(\\s*data'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)balance(?:Before|Of).*<=.*balance(?:After|Of)|ensureBalance|require\\s*\\([^)]*balanceOf[^)]*<='}, {'function.body_not_contains_regex': '(?i)require\\s*\\([^)]*bytes4[^)]*!=\\s*(?:IERC20\\.approve\\.selector|0x095ea7b3)|selector\\s*!=\\s*0x095ea7b3|disallowApprove|allowedMethods\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sharedstake-timelock-call-allows-approve-bypass: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
