"""
fx-pendle-oracle-zero-duration — generated from reference/patterns.dsl/fx-pendle-oracle-zero-duration.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-pendle-oracle-zero-duration.yaml
Source: github:pendle-finance/pendle-core-v2-public@2709ae3
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxPendleOracleZeroDuration(AbstractDetector):
    ARGUMENT = "fx-pendle-oracle-zero-duration"
    HELP = "getMarketLnImpliedRate() calls market.observe(durations) without a zero-duration guard. Passing duration=0 to the TWAP oracle results in observe() returning undefined or stale data (or reverting), breaking callers that pass 0 to mean 'current rate'."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-pendle-oracle-zero-duration.yaml"
    WIKI_TITLE = "getMarketLnImpliedRate missing zero-duration guard — observe(0) returns stale/undefined rate"
    WIKI_DESCRIPTION = "Oracle library functions that accept a duration parameter and pass it to market.observe() must handle duration=0 as a special case returning the spot (current) rate from storage rather than a TWAP. Passing 0 to observe() may revert (if the oracle requires non-zero windows) or silently return stale data, giving callers incorrect implied rates."
    WIKI_EXPLOIT_SCENARIO = "Pendle oracle (2024): integrator calls getMarketLnImpliedRate(market, 0) expecting spot rate. observe(0) is called on the market TWAP contract, which reverts or returns stale data. The integrator's price oracle fails, blocking any operation that depends on fresh implied rate data."
    WIKI_RECOMMENDATION = "Add a duration==0 guard: `if (duration == 0) { return market._storage().lnImpliedRate; }` to return the current spot rate from storage without going through the TWAP path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^getMarketLnImpliedRate$|^getLnImpliedRate'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'getMarketLnImpliedRate|getLnImpliedRate|getRate'}, {'function.body_contains_regex': 'observe\\(|TWAP|durations'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*duration\\s*==\\s*0\\s*\\)|duration\\s*!=\\s*0'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-pendle-oracle-zero-duration: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
