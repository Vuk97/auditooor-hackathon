"""
period-cache-skipped-interval-inflation — generated from reference/patterns.dsl/period-cache-skipped-interval-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py period-cache-skipped-interval-inflation.yaml
Source: code4arena/slice_ab-Ramses-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PeriodCacheSkippedIntervalInflation(AbstractDetector):
    ARGUMENT = "period-cache-skipped-interval-inflation"
    HELP = "Per-period accumulator subtracts endPeriod - startPeriod without filling in skipped periods. If a period had no interaction, its cache slot remains at the previous value — the subtraction then under/overestimates rewards for anyone whose range spans that gap."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/period-cache-skipped-interval-inflation.yaml"
    WIKI_TITLE = "Period accumulator assumes contiguous cache — skipped periods inflate rewards"
    WIKI_DESCRIPTION = "Uniswap-V3-style 'periodCumulativesInside' and similar reward accumulators are correct only if every period's slot is written at that period's boundary. When code touches the cache only on interaction (lazy write), periods with no activity retain a stale value. A downstream reader that does `cache[b] - cache[a]` gets a delta that treats the skipped periods as if they had the same accumulator value"
    WIKI_EXPLOIT_SCENARIO = "Ramses M-01: gauge's `periodCumulativesInside` is keyed by week. A week with no swaps inside the active tick has no update. When a user claims across that week, the reader subtracts `cumulative[week_now] - cumulative[week_when_entered]` but the missing week's entry is whatever the previous week's value was, and the formula interprets that as zero accrual — actually the week's full share of emissio"
    WIKI_RECOMMENDATION = "At read-time, backfill every missing period by linearly extrapolating from the last cached value (or explicitly zeroing the slot if no emissions accrued that period). Alternatively, write the slot in a keeper cron every epoch, at the cost of gas."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(periodCumulative|perEpoch|perPeriod|secondsPerLiquidity|timeWeighted)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(periodCumulative|perEpoch|perPeriod)\\s*\\[\\s*\\w+\\s*\\]'}, {'function.body_contains_regex': '\\[\\s*(endPeriod|toEpoch|endEpoch)\\s*\\]\\s*-\\s*\\[\\s*(startPeriod|fromEpoch|startEpoch)'}, {'function.body_not_contains_regex': 'for\\s*\\(\\s*uint\\w*\\s+\\w+\\s*=\\s*\\w+\\s*;\\s*\\w+\\s*<\\s*\\w*(endPeriod|toEpoch)|_backfill|fillForward|_materializeEpoch'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — period-cache-skipped-interval-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
