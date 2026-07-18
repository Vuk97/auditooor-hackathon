"""
fx-balancer-surge-fee-underflow — generated from reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-balancer-surge-fee-underflow.yaml
Source: github:balancer/balancer-v3-monorepo@767a6a1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxBalancerSurgeFeeUnderflow(AbstractDetector):
    ARGUMENT = "fx-balancer-surge-fee-underflow"
    HELP = "_computeSurgeFee() does not guard against maxSurgeFeePercentage < staticSwapFeePercentage. When the max surge fee is below the static fee, subsequent arithmetic that computes surge range as (maxSurge - staticFee) underflows."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-balancer-surge-fee-underflow.yaml"
    WIKI_TITLE = "Surge fee computation underflows when maxSurgeFeePercentage < staticSwapFeePercentage"
    WIKI_DESCRIPTION = "Hooks that compute a dynamic surge fee as a proportion of the range between staticFeePercentage and maxSurgeFeePercentage will underflow (uint256 wrap) if maxSurgeFeePercentage is less than staticFeePercentage. The result is a massively inflated fee percentage that makes swaps prohibitively expensive or reverts."
    WIKI_EXPLOIT_SCENARIO = "Balancer StableSurgeHook (2024): pool configured with maxSurgeFeePercentage=1% and staticSwapFeePercentage=2%. computeSurgeFee tries to compute (maxSurge - staticFee) = 1% - 2% which underflows in uint256, returning a ~2^256 fee and blocking all swaps."
    WIKI_RECOMMENDATION = "Add a guard at the start of _computeSurgeFee: `if (maxSurgeFeePercentage < staticFeePercentage) return staticFeePercentage;`. The fee can never be below static, so returning static immediately is correct and prevents the underflow."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^_computeSurgeFee$|^surgeFee'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'surgeFee|calcSurge|getSurgeFee'}, {'function.body_contains_regex': 'maxSurgeFeePercentage|surgeFeeData'}, {'function.body_not_contains_regex': 'maxSurgeFeePercentage\\s*<\\s*staticFeePercentage|maxSurgeFee.*staticFee.*return'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-balancer-surge-fee-underflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
