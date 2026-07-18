"""
flashloan-premature-graduation-via-spot — generated from reference/patterns.dsl/flashloan-premature-graduation-via-spot.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py flashloan-premature-graduation-via-spot.yaml
Source: code4arena/slice_ac-Virtuals-M-06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FlashloanPrematureGraduationViaSpot(AbstractDetector):
    ARGUMENT = "flashloan-premature-graduation-via-spot"
    HELP = "Bonding-curve graduation or launch threshold is evaluated against instantaneous pool reserves/balance, so a single-block flashloan can flip the 'graduated' state without organic liquidity."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/flashloan-premature-graduation-via-spot.yaml"
    WIKI_TITLE = "Graduation/launch threshold check uses spot balance, not TWAP"
    WIKI_DESCRIPTION = "A bonding-curve protocol gates graduation on `balanceOf(this) >= THRESHOLD` within one transaction. Because `balanceOf(this)` reflects an instantaneous balance that any caller can inflate via flashloan, an attacker can force-graduate the curve: borrow → deposit → check → withdraw → repay. Post-graduation state (liquidity migration, fee schedule change, reward accrual) is now permanently entered."
    WIKI_EXPLOIT_SCENARIO = "Bonding curve has $900k deposited; threshold is $1M. Attacker flashloans $200k, deposits to push curve balance to $1.1M, calls `checkGraduation()` which flips `graduated = true` and migrates liquidity to a Uniswap pool. Attacker withdraws $200k, repays loan. Protocol is 'launched' at $900k real liquidity, distorting reward schedules and enabling reward capture."
    WIKI_RECOMMENDATION = "Evaluate graduation against a TWAP-integrated or block-averaged deposit figure, or require `block.number > lastMutationBlock` between the deposit that crosses the threshold and the graduation call. Alternatively, snapshot cumulative deposits rather than live balance."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'graduat|launch|LaunchPool|bonding|curve'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(graduated|launched|launchReady|ready)\\s*='}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|reserve0|reserve1|totalSupply\\s*\\(\\s*\\)'}, {'function.body_contains_regex': '(>=|>)\\s*(GRADUATION|LAUNCH|graduationThreshold|launchThreshold|THRESHOLD)'}, {'function.body_not_contains_regex': 'twap|TWAP|observeSingle|observations|cumulativePrice|timeElapsed\\s*>='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — flashloan-premature-graduation-via-spot: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
