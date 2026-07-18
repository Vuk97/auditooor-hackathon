"""
r74-error-swap-both-directions-steal — generated from reference/patterns.dsl/r74-error-swap-both-directions-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-error-swap-both-directions-steal.yaml
Source: r74b-cross-firm-tob+cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74ErrorSwapBothDirectionsSteal(AbstractDetector):
    ARGUMENT = "r74-error-swap-both-directions-steal"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a swap function handles both directions without asserting the K/reserve invariant after the update; asymmetric fee/reserve writes across direction allow round-trip extraction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-error-swap-both-directions-steal.yaml"
    WIKI_TITLE = "Bidirectional swap missing post-swap invariant re-check"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row targets the owned AMM shape where a single public swap branches on zeroForOne, mutates reserve0/reserve1 and feeGrowth fields in both branches, and omits a visible post-swap invariant helper or reserve-product require. The positive fixture models an asymmetric fee leg; the clean fixture keeps the two fee paths symmetric and calls `_checkInvariant(kBe"
    WIKI_EXPLOIT_SCENARIO = "A pool charges fee on input for zeroForOne but derives the reverse-direction fee from output. An attacker swaps token0 to token1 and then token1 to token0, using the branch mismatch to leave reserves and feeGrowth inconsistent because no post-swap K check rejects the round trip."
    WIKI_RECOMMENDATION = "After every swap, assert the AMM invariant holds: `require(newReserve0 * newReserve1 >= oldReserve0 * oldReserve1, 'K');`. For fee-growth-based pools, assert fee accumulators increase monotonically by exactly the delta implied by the swap size. Keep submission_posture NOT_SUBMIT_READY until coverage"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(swap|zeroForOne|direction|tokenIn)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(swap|exchange|swapExactIn|swapExactOut|_swap)$'}, {'function.body_contains_regex': 'zeroForOne|direction|tokenIn\\s*==|isBuy\\s*\\?'}, {'function.body_contains_regex': 'reserve0|reserve1|feeGrowth0|feeGrowth1|protocolFees0|protocolFees1'}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*reserve0\\s*\\*\\s*reserve1\\s*>=|_checkInvariant|_validateK|k_after\\s*>=\\s*k_before|afterInvariant'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-error-swap-both-directions-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
