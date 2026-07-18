"""
safe-approve-non-zero-to-non-zero — generated from reference/patterns.dsl/safe-approve-non-zero-to-non-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py safe-approve-non-zero-to-non-zero.yaml
Source: solodit-cluster-safeapprove-legacy
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SafeApproveNonZeroToNonZero(AbstractDetector):
    ARGUMENT = "safe-approve-non-zero-to-non-zero"
    HELP = "Function calls OpenZeppelin's legacy `safeApprove(spender, amount)` with a non-zero amount without first resetting the allowance to zero. Legacy `safeApprove` reverts in this case. Use `forceApprove` or `safeIncreaseAllowance`."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/safe-approve-non-zero-to-non-zero.yaml"
    WIKI_TITLE = "safeApprove used for non-zero-to-non-zero allowance change"
    WIKI_DESCRIPTION = "OpenZeppelin's legacy `SafeERC20.safeApprove` reverts when called to change an allowance from a non-zero value to another non-zero value. This guard exists to prevent the well-known ERC20 approve-race front-running attack on tokens that do not allow direct `approve` from non-zero to non-zero (e.g. USDT). Callers are expected to first call `safeApprove(spender, 0)` and then `safeApprove(spender, ne"
    WIKI_EXPLOIT_SCENARIO = "A yield vault integrates a router by calling `token.safeApprove(router, amount)` at the start of each deposit cycle. The first cycle succeeds (allowance was 0). Any subsequent cycle where the router did not spend the full amount — common with slippage or partial fills — leaves a non-zero residual allowance. The next `safeApprove` call reverts inside OZ's safety check, and every further deposit thr"
    WIKI_RECOMMENDATION = "Replace `safeApprove(spender, amount)` with `forceApprove(spender, amount)` (OZ SafeERC20 4.9+), which sets the allowance directly and race-safely. If stuck on an older OZ version, first zero the allowance: `token.safeApprove(spender, 0); token.safeApprove(spender, amount);`. For incremental grants,"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.has_high_level_call_named': 'safeApprove'}, {'function.body_contains_regex': '\\.safeApprove\\s*\\(\\s*\\w+\\s*,\\s*(type\\(|uint\\d+\\(|\\d+(?!\\s*[\\)\\s])|\\w+)|SafeERC20\\.safeApprove'}, {'function.body_not_contains_regex': '\\.safeApprove\\s*\\(\\s*\\w+\\s*,\\s*0\\s*\\)|forceApprove|safeIncreaseAllowance|safeDecreaseAllowance'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — safe-approve-non-zero-to-non-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
