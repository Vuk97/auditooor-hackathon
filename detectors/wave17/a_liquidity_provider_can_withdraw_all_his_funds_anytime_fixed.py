"""
a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed — generated from reference/patterns.dsl/a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ALiquidityProviderCanWithdrawAllHisFundsAnytimeFixed(AbstractDetector):
    ARGUMENT = "a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed"
    HELP = "A liquidity provider can withdraw all his funds anytime ✓ Fixed"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed.yaml"
    WIKI_TITLE = "A liquidity provider can withdraw all his funds anytime ✓ Fixed"
    WIKI_DESCRIPTION = "#### Resolution\n\n\n\nThe funds are now locked when the withdrawal is requested, so funds cannot be transferred after the request, and this bug cannot be exploited anymore.\n\n\n#### Description\n\n\nSince some users provide liquidity to sell the insurance policies, it is important that these providers canno"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #13487: #### Resolution\n\n\n\nThe funds are now locked when the withdrawal is requested, so funds cannot be transferred after the request, and this bug cannot be exploited anymore.\n\n\n#### Description\n\n\nSince som"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(requestWithdrawal|getWithdrawalStatus|getDAIToDAIxRatio|balanceOf).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(balance|amount|total|supply|reserve).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-liquidity-provider-can-withdraw-all-his-funds-anytime-fixed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
