"""
oracle-deviation-check-uses-mutable-cached-baseline - generated from reference/patterns.dsl/oracle-deviation-check-uses-mutable-cached-baseline.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-deviation-check-uses-mutable-cached-baseline.yaml
Source: solodit-29924-conic-depeg-cache
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleDeviationCheckUsesMutableCachedBaseline(AbstractDetector):
    ARGUMENT = "oracle-deviation-check-uses-mutable-cached-baseline"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags an oracle consumer that computes a deviation or depeg check against a cached baseline and then refreshes that same baseline inside the update path."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-deviation-check-uses-mutable-cached-baseline.yaml"
    WIKI_TITLE = "Oracle deviation check uses a mutable cached baseline"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned Conic-style shape where a maintenance or oracle-update path compares the current oracle price against a cached baseline, decides whether the asset is depegged or out of bounds, and then overwrites that same cached baseline with the current price. The guard now measures only short-term drift since the last update call, not drift "
    WIKI_EXPLOIT_SCENARIO = "A pool tracks whether an asset has depegged by comparing the latest oracle price to `cachedPrice`. Each keeper-triggered `updateWeights()` call then writes `cachedPrice = currentPrice`. An attacker or market event can walk the asset down in smaller steps between maintenance calls; every step stays inside the local threshold even though the cumulative move from the real peg is large."
    WIKI_RECOMMENDATION = "Compare against a stable anchor that is not rewritten on every update path, or keep a separate immutable/reference baseline for depeg checks. If a rolling cache is still needed for analytics, store it separately from the safety-critical deviation benchmark."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(oracle|priceFeed|getPrice|latestRoundData).*(cachedPrice|lastPrice|priceCache|referencePrice|baselinePrice|pegPrice)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': '(?i)(oracle\\.(price|getPrice|latestAnswer)|priceFeed\\.latestRoundData|getLatestPrice|getPrice\\s*\\()'}, {'function.body_contains_regex': '(?i)(cachedPrice|lastPrice|priceCache|referencePrice|baselinePrice|pegPrice)'}, {'function.body_contains_regex': '(?i)(deviation|depeg|peg|threshold|maxDeviation|maxDelta|drift|diff)'}, {'function.body_ordered_regex': {'first': '(?is)((diff|delta|deviation)\\w*\\s*=\\s*[^;]*(cachedPrice|lastPrice|priceCache|referencePrice|baselinePrice|pegPrice)|abs\\s*\\([^;]*(cachedPrice|lastPrice|priceCache|referencePrice|baselinePrice|pegPrice))', 'second': '(cachedPrice|lastPrice|priceCache|referencePrice|baselinePrice|pegPrice)\\s*=\\s*(currentPrice|newPrice|latestPrice|oraclePrice|price)', 'ignore_comments_and_strings': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - oracle-deviation-check-uses-mutable-cached-baseline: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
