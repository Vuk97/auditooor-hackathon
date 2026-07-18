"""
glider-band-oracle-no-staleness-check — generated from reference/patterns.dsl/glider-band-oracle-no-staleness-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-band-oracle-no-staleness-check.yaml
Source: hexens-glider/band-oracle-price-data-is-not-validated-for-stalen
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderBandOracleNoStalenessCheck(AbstractDetector):
    ARGUMENT = "glider-band-oracle-no-staleness-check"
    HELP = "Band oracle `getReferenceData(...)` returns `(rate, lastUpdatedBase, lastUpdatedQuote)` — consumer does not validate rate > 0 nor base/quote staleness."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-band-oracle-no-staleness-check.yaml"
    WIKI_TITLE = "Band oracle read without rate / staleness validation"
    WIKI_DESCRIPTION = "Band Protocol's IStdReference exposes `getReferenceData(base, quote)` returning a struct with `rate`, `lastUpdatedBase`, `lastUpdatedQuote`. All three require validation: `rate > 0` and both timestamps within a staleness window. Omitting any check lets a price-dependent action proceed on stale or invalid data."
    WIKI_EXPLOIT_SCENARIO = "Contract pulls rate and immediately multiplies against user deposit. Both timestamps are 3 hours old due to a feed outage; price has since moved 8%. Attacker deposits at the stale favourable price, withdraws after new price updates, profits the difference."
    WIKI_RECOMMENDATION = "After `getReferenceData` call: `require(d.rate > 0); require(block.timestamp - d.lastUpdatedBase <= MAX_STALE); require(block.timestamp - d.lastUpdatedQuote <= MAX_STALE);`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'getReferenceData|IStdReference|ReferenceData|bandOracle|IBandOracle'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'getReferenceData\\s*\\(|ReferenceData\\s+memory'}, {'function.body_not_contains_regex': 'lastUpdatedBase|lastUpdatedQuote|rate\\s*>\\s*0|\\.rate\\s*>\\s*0|require\\s*\\(\\s*\\w*rate'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-band-oracle-no-staleness-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
