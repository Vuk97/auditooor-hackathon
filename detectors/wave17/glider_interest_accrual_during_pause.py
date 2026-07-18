"""
glider-interest-accrual-during-pause — generated from reference/patterns.dsl/glider-interest-accrual-during-pause.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-interest-accrual-during-pause.yaml
Source: hexens-glider/interest-accruals-when-contract-is-paused
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderInterestAccrualDuringPause(AbstractDetector):
    ARGUMENT = "glider-interest-accrual-during-pause"
    HELP = "Protocol pauses repay / liquidation but interest still accrues. When unpaused, positions are unfairly liquidatable at the post-pause LTV even though the user had no way to repay during the outage."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-interest-accrual-during-pause.yaml"
    WIKI_TITLE = "Interest accrues while protocol paused — unfair liquidation"
    WIKI_DESCRIPTION = "Pausable lending protocols that gate `repay`/`borrow` with `whenNotPaused` but leave `accrueInterest` unguarded accumulate silent debt during an outage. When the admin unpauses, every position that was healthy at pause time may be underwater, and bots race to liquidate them. This is a repeated pattern in BendDAO-style lending forks."
    WIKI_EXPLOIT_SCENARIO = "Admin pauses the pool for a router upgrade. 4 hours later unpaused. Interest accrued = 4h × rate. Borrower with 80% LTV at pause-time is now at 82% LTV (liquidation threshold) without any ability to top up or repay during the window. Liquidation bot sweeps the entire market."
    WIKI_RECOMMENDATION = "Either gate `accrueInterest` with the same `whenNotPaused` as repay, OR cap accrued interest across a pause: record `pauseStart` and when unpausing, skip the paused-duration from `secondsSinceLastAccrual` before compounding."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'whenNotPaused|_pause\\s*\\(|paused'}, {'contract.has_function_matching': '^(accrue|accrueInterest|updateInterest|calculateInterest|_accrue|_updateInterest)$'}]
    _MATCH = [{'function.name_matches': '^(accrue|accrueInterest|updateInterest|calculateInterest|_accrue|_updateInterest)$'}, {'function.kind': 'external_or_public'}, {'function.has_modifier': {'includes': ['whenNotPaused', 'notPaused', 'ifNotPaused'], 'negate': True}}, {'function.body_not_contains_regex': 'paused\\s*\\(\\s*\\)|_paused|isPaused'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-interest-accrual-during-pause: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
