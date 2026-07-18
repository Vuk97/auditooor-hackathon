"""
matching-engine-reduce-only-oi-accounting-gap — generated from reference/patterns.dsl/matching-engine-reduce-only-oi-accounting-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py matching-engine-reduce-only-oi-accounting-gap.yaml
Source: auditooor/roadmap-slice28-matching-engine-recall
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MatchingEngineReduceOnlyOiAccountingGap(AbstractDetector):
    ARGUMENT = "matching-engine-reduce-only-oi-accounting-gap"
    HELP = "Perps order path increments open interest without excluding reduce-only orders."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/matching-engine-reduce-only-oi-accounting-gap.yaml"
    WIKI_TITLE = "Reduce-only orders increase open-interest accounting"
    WIKI_DESCRIPTION = "Reduce-only orders are intended to decrease or cap position risk. If the order lifecycle increments quote/base open interest for all placements without branching on reduceOnly, risk counters drift upward and max-OI guardrails can halt otherwise valid matching."
    WIKI_EXPLOIT_SCENARIO = "An attacker repeatedly places and cancels reduce-only orders. Every placement increments OI even though the order cannot increase exposure, eventually tripping max-OI and blocking legitimate order placement."
    WIKI_RECOMMENDATION = "Only increment OI for orders that can increase exposure; mirror the same accounting on cancel/fill paths and add reduce-only lifecycle neutrality tests."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(reduceOnly|reduce_only|ReduceOnly)'}, {'contract.source_matches_regex': '(quoteOI|baseOI|openInterest|maxOI|MAX_OI)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(placeOrder|submitOrder|_addOrder|_insertOrder|matchOrder)'}, {'function.body_contains_regex': '((quoteOI|baseOI|openInterest)\\s*\\+=|increaseOI\\s*\\()'}, {'function.body_not_contains_regex': '(\\!\\s*\\w+\\.reduceOnly|if\\s*\\([^)]*reduceOnly|reduceOnly\\s*==\\s*false|require\\s*\\([^)]*\\!\\s*[^)]*reduceOnly)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — matching-engine-reduce-only-oi-accounting-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
