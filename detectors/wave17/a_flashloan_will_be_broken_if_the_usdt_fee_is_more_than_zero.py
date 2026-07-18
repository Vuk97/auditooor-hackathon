"""
a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero — generated from reference/patterns.dsl/a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AFlashloanWillBeBrokenIfTheUsdtFeeIsMoreThanZero(AbstractDetector):
    ARGUMENT = "a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero"
    HELP = "A flashloan will be broken if the USDT fee is more than zero"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero.yaml"
    WIKI_TITLE = "A flashloan will be broken if the USDT fee is more than zero"
    WIKI_DESCRIPTION = "Let's take a look at the flashloan flow. After doTransferOut a receiver gets `amount - fee`.\nhttps://github.com/ibdotxyz/compound-protocol/blob/8cd45803b48552e344e22be280c9e1c03ec8644a/contracts/CCollateralCapErc20.sol#L217\n\nThen a receiver's `onFlashLoan` function will be called w"
    WIKI_EXPLOIT_SCENARIO = "A flashloan will be broken if the USDT fee is more than zero"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'onFlashLoan|require'}, {'function.body_not_contains_regex': 'accrue|update|sync|validate|check|refresh'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-flashloan-will-be-broken-if-the-usdt-fee-is-more-than-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
