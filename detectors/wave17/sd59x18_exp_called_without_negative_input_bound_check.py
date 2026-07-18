"""
sd59x18-exp-called-without-negative-input-bound-check — generated from reference/patterns.dsl/sd59x18-exp-called-without-negative-input-bound-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sd59x18-exp-called-without-negative-input-bound-check.yaml
Source: lisa-mine-r99-case-05975-c4-pooltogether-cgda-liquidator-2023-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Sd59x18ExpCalledWithoutNegativeInputBoundCheck(AbstractDetector):
    ARGUMENT = "sd59x18-exp-called-without-negative-input-bound-check"
    HELP = "Function calls `SD59x18.exp()` (PRBMath signed-fixed-point exponential) on a derived value without bounding the input from below. PRBMath's `exp` reverts on inputs < `MIN_WHOLE_SD59x18` (≈ -41.4 in wrapped units). Pricing / decay / GDA logic that lets time-since-event grow unboundedly will revert th"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sd59x18-exp-called-without-negative-input-bound-check.yaml"
    WIKI_TITLE = "SD59x18.exp() called with no `< MIN_EXP` lower-bound check"
    WIKI_DESCRIPTION = "Pattern fires on functions that call `<SD59x18-value>.exp()` on a value derived from `block.timestamp - lastEvent` (or similar elapsed-time term) without a lower-bound check. PRBMath's `exp` reverts when input < approx `-41.4 * 1e18` (the value below which the result would underflow to zero). Any pricing or emission helper that relies on the call to return zero for very-negative inputs (a natural "
    WIKI_EXPLOIT_SCENARIO = "PoolTogether's `ContinuousGDA.purchasePrice` computes `exp(-decayConstant * elapsedSinceLastSale)`. After a 7-day liquidator-pool quiet period, `elapsedSinceLastSale` becomes large and the exp argument drops below `MIN_WHOLE_SD59x18`. PRBMath reverts. `purchasePrice` reverts on every read; the bonding curve goes dark and the pool can no longer liquidate yield — the very state where it most needs t"
    WIKI_RECOMMENDATION = "Clamp the input before calling exp: `if (x < MIN_WHOLE_SD59x18 + 1) return sd(0);` or use the `expSafe`-style wrapper the protocol exports (verify it returns 0 on underflow rather than reverting). Add a regression test that fuzzes `elapsedSinceLastSale` over the full uint256 range and asserts `purch"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'SD59x18|UD60x18|PRBMath|sd59x18|prb-math'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\.exp\\s*\\(\\s*\\)|PRBMathSD59x18\\.exp\\s*\\(|prb_math::exp'}, {'function.body_not_contains_regex': '\\b(sd|wrap|abs)\\s*\\(\\s*[A-Za-z_][A-Za-z0-9_]*\\s*\\)\\s*<\\s*sd\\s*\\(|<\\s*-1e18|<\\s*MIN_EXP|>\\s*MIN_WHOLE_SD59x18|isLte|require\\s*\\([^)]*<\\s*[A-Za-z_]+_(MIN|MAX)|MIN_EXP|EXP_MIN_INPUT'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — sd59x18-exp-called-without-negative-input-bound-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
