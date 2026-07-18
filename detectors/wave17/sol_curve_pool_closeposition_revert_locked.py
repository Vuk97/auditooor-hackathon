"""
sol-curve-pool-closeposition-revert-locked — generated from reference/patterns.dsl/sol-curve-pool-closeposition-revert-locked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-curve-pool-closeposition-revert-locked.yaml
Source: solodit-cluster-C0092
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolCurvePoolClosepositionRevertLocked(AbstractDetector):
    ARGUMENT = "sol-curve-pool-closeposition-revert-locked"
    HELP = "Curve close-position uses calc_withdraw_one_coin as its own min_amount — brittle against small rounding, locks positions."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-curve-pool-closeposition-revert-locked.yaml"
    WIKI_TITLE = "Curve close-position revert (min_amount computed in-tx)"
    WIKI_DESCRIPTION = "`calc_withdraw_one_coin` is a view helper that returns the expected output. Using its return value directly as `min_amount` to `remove_liquidity_one_coin` provides zero slippage protection AND causes a revert when Curve's internal fee/rounding differs by 1 wei from the view call."
    WIKI_EXPLOIT_SCENARIO = "ConvexSpell 2024: users couldn't call `closePositionFarm` because the min_amount computation disagreed by 1 wei with Curve's actual remove-liquidity. Positions remained on-chain until owner intervention."
    WIKI_RECOMMENDATION = "Compute `min_amount = calc_withdraw_one_coin(...) * (BPS - slippage) / BPS` with a small slippage buffer. Never pass the raw view output as the minimum."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ICurvePool|remove_liquidity|StableSwap|CurveSpell|ConvexSpell'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(closePosition|exit|unwind|redeem|closeFarm)[A-Z]?'}, {'function.body_contains_regex': 'remove_liquidity|removeLiquidityOneCoin'}, {'function.body_contains_regex': 'calc_withdraw_one_coin|calc_token_amount'}, {'function.body_not_contains_regex': 'try\\s+|catch|minAmount\\s*=\\s*0|slippage_exempt|_applySlippageCap'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-curve-pool-closeposition-revert-locked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
