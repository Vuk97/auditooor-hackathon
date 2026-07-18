"""
decimal-precision-18-to-6-downscale-loss — generated from reference/patterns.dsl/decimal-precision-18-to-6-downscale-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py decimal-precision-18-to-6-downscale-loss.yaml
Source: solodit/C0255
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DecimalPrecision18To6DownscaleLoss(AbstractDetector):
    ARGUMENT = "decimal-precision-18-to-6-downscale-loss"
    HELP = "18-to-6 decimal downscale (e.g. `/ 1e12`) without ceiling rounding. Small amounts floor to zero — deposit is booked but zero tokens are credited."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/decimal-precision-18-to-6-downscale-loss.yaml"
    WIKI_TITLE = "18->6 decimal downscale rounds to zero (no ceiling)"
    WIKI_DESCRIPTION = "The conversion from an internal 18-decimal accounting unit to a 6-decimal token (USDC / USDT) divides by 1e12 (or multiplies by 1e12 inversely, or shifts 40 bits) using floor division. Any amount below 1e12 rounds down to zero. Depositors whose input converts to a sub-1e12 remainder have their deposit accepted on the books while receiving zero credit on-chain, and the protocol accumulates dust it "
    WIKI_EXPLOIT_SCENARIO = "A vault stores shares in 18-decimal precision and pays out in USDC. The withdraw path computes `amount6 = shares * price / 1e12` with no ceiling adjustment. A user whose `shares * price` product is 9.9e11 receives zero USDC but has their share balance cleared. Over many users this silently drains the dust into the protocol's general balance. An attacker who deposits 1e11 of value likewise pays the"
    WIKI_RECOMMENDATION = "Round the downscale direction defensively: for user deposits, ceil-divide so one unit is always credited when any non-zero accounting amount is moved; for protocol-to-user payouts, use floor division (as now) but additionally require the rounded-down amount is strictly positive and revert on zero. U"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\/\\s*1e12\\b|\\*\\s*1e12\\b|>>\\s*40|scaleDown|downscale|toE6|to6Decimals'}, {'function.body_not_contains_regex': 'ceilDiv|Math\\.ceilDiv|mulDivRoundingUp|\\+\\s*1e12\\s*-\\s*1|roundUp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — decimal-precision-18-to-6-downscale-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
