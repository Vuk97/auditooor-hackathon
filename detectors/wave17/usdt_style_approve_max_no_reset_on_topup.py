"""
usdt-style-approve-max-no-reset-on-topup — generated from reference/patterns.dsl/usdt-style-approve-max-no-reset-on-topup.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py usdt-style-approve-max-no-reset-on-topup.yaml
Source: auditooor-R82-polymarket-UmaCtfAdapter-requestPrice
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UsdtStyleApproveMaxNoResetOnTopup(AbstractDetector):
    ARGUMENT = "usdt-style-approve-max-no-reset-on-topup"
    HELP = "Function checks `allowance < required` then `approve(spender, type(uint256).max)`. For USDT-style tokens that require allowance reset to zero before a non-zero write, the second call reverts. A partially-consumed prior allowance silently bricks the flow."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/usdt-style-approve-max-no-reset-on-topup.yaml"
    WIKI_TITLE = "Conditional max-approve without zero-reset — USDT-style tokens brick on second top-up"
    WIKI_DESCRIPTION = "A common 'lazy re-approve' pattern: `if (allowance(this, spender) < required) { approve(spender, type(uint256).max); }`. The `if` is intended as a gas optimisation to skip needless approvals. But for tokens that enforce non-zero-to-non-zero revert (USDT on mainnet, BNB tokens, others), the second approve reverts whenever the allowance has been partially consumed to a value strictly below `required"
    WIKI_EXPLOIT_SCENARIO = "UmaCtfAdapter is configured with USDT as rewardToken (plausible for a long-tail question). First `initialize(q1)` approves uint256.max to OO, spends `reward1`. Allowance now `max - reward1`, still > reward2. Years pass; accumulated requests reduce allowance to 500 USDT while `reward2 = 1000 USDT`. Next `initialize(q2)` hits the `if` branch, issues `approve(OO, max)` — USDT reverts on non-zero-to-n"
    WIKI_RECOMMENDATION = "Use `forceApprove` (OZ SafeERC20 4.9+) which emits a zero-reset then the new allowance race-safely. OR explicitly reset: `token.approve(spender, 0); token.approve(spender, type(uint256).max);`. OR replace the lazy pattern with `safeIncreaseAllowance(spender, delta)` that computes the delta. Also con"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)IERC20|SafeERC20|rewardToken|currency'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)_?(requestPrice|approveSpender|fund\\w*|_?topUp|_?init\\w*)'}, {'function.body_contains_regex': '(?i)\\.approve\\s*\\(\\s*\\w+\\s*,\\s*type\\s*\\(\\s*uint256\\s*\\)\\s*\\.\\s*max\\s*\\)|\\.approve\\s*\\(\\s*\\w+\\s*,\\s*uint256\\s*\\(\\s*-\\s*1\\s*\\)\\s*\\)|\\.approve\\s*\\(\\s*\\w+\\s*,\\s*2\\s*\\*\\*\\s*256\\s*-\\s*1\\s*\\)'}, {'function.body_contains_regex': '(?i)allowance\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*,'}, {'function.body_not_contains_regex': '(?i)\\.approve\\s*\\(\\s*\\w+\\s*,\\s*0\\s*\\)|forceApprove|safeIncreaseAllowance|safeDecreaseAllowance'}, {'function.not_in_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — usdt-style-approve-max-no-reset-on-topup: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
