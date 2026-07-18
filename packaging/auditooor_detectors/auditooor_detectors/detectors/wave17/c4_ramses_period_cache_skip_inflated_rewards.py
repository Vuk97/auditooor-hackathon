"""
c4-ramses-period-cache-skip-inflated-rewards — generated from reference/patterns.dsl/c4-ramses-period-cache-skip-inflated-rewards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-ramses-period-cache-skip-inflated-rewards.yaml
Source: code4arena/2024-10-ramses-exchange-M01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4RamsesPeriodCacheSkipInflatedRewards(AbstractDetector):
    ARGUMENT = "c4-ramses-period-cache-skip-inflated-rewards"
    HELP = "Per-period reward cache assumes contiguous periods — skipping a period inflates rewards the next time."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-ramses-period-cache-skip-inflated-rewards.yaml"
    WIKI_TITLE = "Period cumulatives cache misattributes skipped periods"
    WIKI_DESCRIPTION = "Time-weighted reward accounting caches a per-period snapshot (seconds-per-liquidity, cumulative volume). When no one pokes the gauge during a period, the next poke must fill the gap period-by-period; simply computing delta = current - cached misattributes the entire gap to the current period, over-paying current stakers."
    WIKI_EXPLOIT_SCENARIO = "Ramses V3 C4-2024-10 M-01: gauge period-cache silently skipped weeks with zero activity. Returning liquidity in week N+2 received rewards as if they had been active for all intervening weeks, diluting the emission budget for pools that were active those weeks."
    WIKI_RECOMMENDATION = "Iterate `while (cachedPeriod < currentPeriod) { _settlePeriod(cachedPeriod); cachedPeriod++; }` so each period writes its own cache entry. Or require pokes at least once per period via a keeper."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'GaugeV3|periodCumulativesInside|secondsPerLiquidity|lastUpdatePeriod'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'periodCumulatives|cumulativesInside|secondsPerLiquidity'}, {'function.body_contains_regex': 'lastUpdatePeriod|cachedPeriod|periodCache'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*currentPeriod\\s*==\\s*lastUpdatePeriod\\s*\\+\\s*1|_fillGap|if\\s*\\(\\s*period\\s*>\\s*lastPeriod\\s*\\+\\s*1'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-ramses-period-cache-skip-inflated-rewards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
