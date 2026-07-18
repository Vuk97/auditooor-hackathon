"""
pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves - generated from reference/patterns.dsl/pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves.yaml
Source: auditooor-R76-rekt-woofi-2024
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PmmQuoteReadsExternalOracleWithoutDeviationBandVsReserves(AbstractDetector):
    ARGUMENT = "pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags the owned PMM quote path that reads a single external oracle price inside a quote-like external function with reserve-context math and no visible deviation-band or secondary-oracle guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves.yaml"
    WIKI_TITLE = "PMM quote uses one oracle price without reserve-band cross-check"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves only the owned WooFi-style PMM quote shape where an external `querySwap`/`getQuote` path reads `oracle.price(...)` or `oracle.getPrice(...)`, references reserve context in the same function, and uses the oracle price in quote math without a visible deviation band or secondary oracle. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "A PMM swap path reads a manipulated external oracle price and quotes against it immediately. Because the quote function does not sanity-band that price against reserve-derived context or a second feed, a thin upstream market move can flow directly into the PMM's output amount."
    WIKI_RECOMMENDATION = "Add a same-function deviation guard between the primary oracle and either a reserve-derived reference price or a secondary oracle, e.g. `require(diff * 1e4 / referencePrice <= deviationBps)`, and keep this row NOT_SUBMIT_READY until evidence extends beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(oracle|IWooOracle|IWooracle).*(baseReserve|quoteReserve|baseBalance|quoteBalance|pmmState|reserveRatio)'}]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^swap$|querySwap|_swap|sPMMSwap|pmmSwap|quoteSwap|getQuote'}, {'function.body_contains_regex': '(?i)oracle\\.(latestAnswer|getPrice|price)|IWooracle|IWooOracle|priceFeed\\.'}, {'function.body_contains_regex': '(?i)(baseReserve|quoteReserve|baseBalance|quoteBalance|reserveRatio|poolRatio|pmmState)'}, {'function.body_not_contains_regex': '(?i)deviationBps|deviationBand|chainlinkFallback|secondaryOracle|abs\\(oracleP - poolRatio\\)|require\\s*\\([^;]*maxDeviation|safetyRange'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - pmm-quote-reads-external-oracle-without-deviation-band-vs-reserves: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
