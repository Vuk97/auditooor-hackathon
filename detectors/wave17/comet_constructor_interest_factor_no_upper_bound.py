"""
comet-constructor-interest-factor-no-upper-bound — generated from reference/patterns.dsl/comet-constructor-interest-factor-no-upper-bound.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-constructor-interest-factor-no-upper-bound.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-7f1ff0dc4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometConstructorInterestFactorNoUpperBound(AbstractDetector):
    ARGUMENT = "comet-constructor-interest-factor-no-upper-bound"
    HELP = "Constructor / initialize writes `reserveRate` or `kink` directly from the configuration without bounding them to the fixed-point scale (`<= FACTOR_SCALE`). A governance misconfiguration or buggy deploy script can set `kink > 1e18`, which breaks the piecewise interest-rate model: the 'high utilisatio"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-constructor-interest-factor-no-upper-bound.yaml"
    WIKI_TITLE = "Interest-model factor accepted without upper-bound check in constructor"
    WIKI_DESCRIPTION = "Piecewise-linear interest rate models use fixed-point factors to represent fractions: `reserveRate` (fraction of interest sent to reserves, must be `<= 1`) and `kink` (utilisation threshold where the rate slope changes, also `<= 1`). Both are stored as scaled integers in `[0, FACTOR_SCALE]`. An `initialize` path that assigns these from a user-provided configuration struct without bounds-checking a"
    WIKI_EXPLOIT_SCENARIO = "Comet's original `initialize` did not bound `reserveRate` or `kink` (ChainSecurity 5.13, fixed in commit 7f1ff0dc4f which added `if (config.reserveRate > FACTOR_SCALE) revert BadReserveRate();` / `if (config.kink > FACTOR_SCALE) revert BadKink();`). A governance proposal or mis-deploy sets `kink = type(uint64).max`. The piecewise rate `utilization > kink` branch never fires, so borrow rates stay a"
    WIKI_RECOMMENDATION = "At initialization, bound-check every fraction-typed parameter: `if (config.reserveRate > FACTOR_SCALE) revert BadReserveRate(); if (config.kink > FACTOR_SCALE) revert BadKink(); if (config.baseScale < BASE_ACCRUAL_SCALE) revert BadDecimals();`. Also check the relationship invariants in the piecewise"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'reserveRate|kink|FACTOR_SCALE|BASE_ACCRUAL_SCALE|perSecondInterestRate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|_initialize|constructor|setParameters|updateInterestParams|setIRMParams)$'}, {'function.body_contains_regex': '(reserveRate|kink|supplyKink|borrowKink)\\s*=\\s*[A-Za-z_]+\\.[A-Za-z_]+|reserveRate\\s*=\\s*config\\.|kink\\s*=\\s*config\\.'}, {'function.body_not_contains_regex': '(reserveRate|kink)\\s*>\\s*FACTOR_SCALE|(reserveRate|kink)\\s*>\\s*1e18|BadReserveRate|BadKink'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-constructor-interest-factor-no-upper-bound: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
