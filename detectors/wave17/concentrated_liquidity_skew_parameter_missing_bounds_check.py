"""
concentrated-liquidity-skew-parameter-missing-bounds-check — generated from reference/patterns.dsl/concentrated-liquidity-skew-parameter-missing-bounds-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py concentrated-liquidity-skew-parameter-missing-bounds-check.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-43
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConcentratedLiquiditySkewParameterMissingBoundsCheck(AbstractDetector):
    ARGUMENT = "concentrated-liquidity-skew-parameter-missing-bounds-check"
    HELP = "Range / SCL validate() checks bounds/spread/fee but silently accepts the `skew` parameter. Extreme skew inflates amount_in_slice() and drains pooled balance from other liquidity providers."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/concentrated-liquidity-skew-parameter-missing-bounds-check.yaml"
    WIKI_TITLE = "SCL range `skew` parameter missing bounds check → phantom reserves + cross-LP drain"
    WIKI_DESCRIPTION = "In a Skewed Concentrated Liquidity (SCL) style DEX, the per-range config includes a `skew` coefficient documented in [-1, 1]. The `validate()` entrypoint checks bounds / spread / fee / tick, but never validates skew even though an `InvalidSkew` error variant is defined. Unbounded skew breaks the internal math: `beta = skew / delta_p`, `alpha = 1 - beta * p_m` — plugging skew = 100 into a narrow ra"
    WIKI_EXPLOIT_SCENARIO = "Attacker creates a range with `skew = 100`, narrow bounds [1.0, 1.1], and 1M base/quote reserves. `amount_in_slice` with skew=3 already reports 6.41M tokens when only 1M exist (+541% phantom). Attacker swaps against their own range, receives real tokens from the pooled contract balance — actually coming from other LPs. When honest LPs attempt to close their own ranges, the pool is short the stolen"
    WIKI_RECOMMENDATION = "Add `ensure!(self.skew >= SignedDecimal::negative_one() && self.skew <= SignedDecimal::one(), RangeError::InvalidSkew {})` to `validate()`. More generally, every user-supplied math coefficient (skew, curvature, weight) MUST have an explicit range check in validate(). Audit hint: grep for ErrorKind v"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$|ranges|scl|concentrated'}, {'contract.has_function_matching': '(?i)validate|configure|new_range'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)validate|configure|sanity_check|check_params|create_range|validate_range'}, {'function.body_contains_regex': '(?i)high\\s*>\\s*low|InvalidBounds|InvalidSpread|validate_price'}, {'function.body_not_contains_regex': '(?i)skew\\s*[<>=]=?|InvalidSkew|SignedDecimal::negative_one|skew\\s+within|clamp.*skew|skew\\s*\\.abs\\(\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — concentrated-liquidity-skew-parameter-missing-bounds-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
