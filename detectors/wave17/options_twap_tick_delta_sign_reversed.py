"""
options-twap-tick-delta-sign-reversed — generated from reference/patterns.dsl/options-twap-tick-delta-sign-reversed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py options-twap-tick-delta-sign-reversed.yaml
Source: auditooor-R75-c4-2024-04-panoptic-H516
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptionsTwapTickDeltaSignReversed(AbstractDetector):
    ARGUMENT = "options-twap-tick-delta-sign-reversed"
    HELP = "TWAP tick calculation subtracts `older - newer` instead of `newer - older` from the Uniswap `tickCumulatives` array. Since cumulative values are monotonic, the returned TWAP has inverted sign — downstream comparators (liquidation guards, ITM/OTM checks, force-exercise validation) all behave inversel"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/options-twap-tick-delta-sign-reversed.yaml"
    WIKI_TITLE = "TWAP tick computed with reversed subtraction on Uniswap tickCumulatives"
    WIKI_DESCRIPTION = "Uniswap v3's `observe` returns cumulative tick values at given seconds-ago offsets. The TWAP tick between observation N and observation N+1 (N is newer) must be `(cum[N] - cum[N+1]) / dt`. Some implementations iterate with `cum[i] - cum[i+1]` where the array is indexed oldest-first, reversing the subtraction. Because cumulatives grow monotonically, the result is the additive inverse of the true TW"
    WIKI_EXPLOIT_SCENARIO = "(1) Uniswap pool drifted by ~100 ticks over the past 5 minutes (normal). True TWAP delta tick vs. now is small (~50 ticks). (2) `twapFilter` iterates with `tickCumulatives[i] - tickCumulatives[i+1]` on a seconds-ago array `[0, 30, 60, ..., 570]` where index 0 is newest. (3) Subtracting newer minus older on an oldest-first layout yields NEGATIVE deltas; the median comes out as approximately -50 tic"
    WIKI_RECOMMENDATION = "Pin down a single convention: if the array is `secondsAgos = [0, X, 2X, ...]` newest-first, then `delta = cum[i] - cum[i+1]` IS correct (index 0 is newer, index 1 is older). If the API returns oldest-first (reverse), flip to `cum[i+1] - cum[i]`. Unit-test with a hand-constructed monotonic cumulative"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(twapFilter|twapTick|getTwap|computeTWAP|observe|tickCumulatives)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(twapFilter|computeTwap|_getTwap|getUniV3TWAP|observeTwap|medianTwap)'}, {'function.body_contains_regex': 'tickCumulatives\\[\\s*(i|idx)\\s*\\]\\s*-\\s*tickCumulatives\\[\\s*(i|idx)\\s*\\+\\s*1\\s*\\]'}, {'function.body_not_contains_regex': 'tickCumulatives\\[\\s*(i|idx)\\s*\\+\\s*1\\s*\\]\\s*-\\s*tickCumulatives\\[\\s*(i|idx)\\s*\\]'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — options-twap-tick-delta-sign-reversed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
