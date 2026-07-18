"""
fx-euler-liquidation-zero-liability-divzero — generated from reference/patterns.dsl/fx-euler-liquidation-zero-liability-divzero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-liquidation-zero-liability-divzero.yaml
Source: github:euler-xyz/euler-vault-kit@2f935f5
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerLiquidationZeroLiabilityDivzero(AbstractDetector):
    ARGUMENT = "fx-euler-liquidation-zero-liability-divzero"
    HELP = "Liquidation logic checks collateralAdjustedValue > liabilityValue to detect no-violation but misses liabilityValue == 0. When a borrower has zero debt, division by liabilityValue in the discount calculation panics (division by zero)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-liquidation-zero-liability-divzero.yaml"
    WIKI_TITLE = "Liquidation missing zero liability guard — division-by-zero panic on healthy zero-debt position"
    WIKI_DESCRIPTION = "Liquidation modules that compute a discount factor by dividing collateral by liability value will panic with a division-by-zero if liabilityValue is 0 but collateralAdjustedValue is also 0 (e.g., a dust position). The no-violation early-return only checks collateralAdjustedValue > liabilityValue, so the 0/0 case falls through to the discount computation."
    WIKI_EXPLOIT_SCENARIO = "Euler Cantina-43/508 (2024): a borrower with zero liability and zero collateral triggers liquidation. The check collateralValue > 0 passes (both are 0, so check is false), the code falls through to compute discount = collateral * SCALE / liabilityValue → division by zero → panic revert."
    WIKI_RECOMMENDATION = "Add `|| liabilityValue == 0` to the early-return condition: `if (collateralAdjustedValue > liabilityValue || liabilityValue == 0) return;`"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^liquidat|^checkLiquid|^calculateLiquid'}]
    _MATCH = [{'function.kind': 'internal_or_external_or_public'}, {'function.name_matches': 'liquidat|[Ll]iquid'}, {'function.body_contains_regex': 'liabilityValue|collateralAdjustedValue'}, {'function.body_not_contains_regex': 'liabilityValue\\s*==\\s*0|liabilityValue\\s*>\\s*0'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-liquidation-zero-liability-divzero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
