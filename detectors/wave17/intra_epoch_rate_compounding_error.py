"""
intra-epoch-rate-compounding-error — generated from reference/patterns.dsl/intra-epoch-rate-compounding-error.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py intra-epoch-rate-compounding-error.yaml
Source: solodit/C0364
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IntraEpochRateCompoundingError(AbstractDetector):
    ARGUMENT = "intra-epoch-rate-compounding-error"
    HELP = "Interest-rate update (rateAtTarget / adjustRate) is applied intra-epoch without an epoch-boundary guard, so rate errors compound across partial windows."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/intra-epoch-rate-compounding-error.yaml"
    WIKI_TITLE = "Intra-epoch rate update compounds rate-at-target error"
    WIKI_DESCRIPTION = "Lending protocols that derive a rate-at-target from utilization (Morpho adaptive curve IRM, Aave-style rate strategies, Compound forks) assume the rate formula is re-solved once per epoch. When _updateInterestRate / updateRate / adjustRate is invoked intra-epoch — on every borrow, repay, liquidate, or flashloan — the rateAtTarget adjustment is applied repeatedly over partial time windows. Because "
    WIKI_EXPLOIT_SCENARIO = "Reserve runs with epochDuration = 12 hours. A searcher spams 1-wei borrow / repay every block against the pool. Each call triggers _updateInterestRate, which reads the instantaneous utilization and nudges rateAtTarget. Over one epoch the expected update is a single monotonic adjustment; instead the rate receives thousands of tiny intra-epoch adjustments whose compounded product diverges from the a"
    WIKI_RECOMMENDATION = "Gate rate-at-target recomputation on an epoch boundary: if (block.timestamp - lastUpdate < epochDuration) skip the rateAtTarget adjustment and only accrue interest on the current index. Alternatively, cache the intended new rateAtTarget and defer its application until the next newEpoch() / epochBoun"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(rateAtTarget|rate|utilization|epoch|lastUpdate)'}]
    _MATCH = [{'function.name_matches': '(_updateInterestRate|updateRate|_updateRate|adjustRate|recalcRate)'}, {'function.body_contains_regex': {'regex': '(rateAtTarget|adjustRate|utilization.*rate|rate.*utilization)'}}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*-\\s*lastUpdate\\s*>=?\\s*\\w*[Ee]poch|lastUpdate\\s*\\+\\s*\\w*[Ee]poch|newEpoch|epochBoundary|isNewEpoch'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — intra-epoch-rate-compounding-error: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
