"""
certora-compound-collateral-factor-bounded — generated from reference/patterns.dsl/certora-compound-collateral-factor-bounded.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-compound-collateral-factor-bounded.yaml
Source: certora-compound-v2/Comptroller/collateralFactorBounded
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraCompoundCollateralFactorBounded(AbstractDetector):
    ARGUMENT = "certora-compound-collateral-factor-bounded"
    HELP = "Compound-style `setCollateralFactor` does not enforce the max-CF bound — Certora `collateralFactorBounded` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-compound-collateral-factor-bounded.yaml"
    WIKI_TITLE = "Collateral factor setter missing max-mantissa bound (Compound invariant)"
    WIKI_DESCRIPTION = "Compound v2's Certora spec proves `collateralFactorMantissa[market] <= collateralFactorMaxMantissa` for every supported market. The max protects against admin mistakes that would let users borrow ≥100% of their collateral value. A setter that admits an arbitrary mantissa lets a faulty governance tx (or compromised timelock) raise CF to 2e18 — instantly bad-debt across every user of that market."
    WIKI_EXPLOIT_SCENARIO = "A new admin calls `_setCollateralFactor(cDAI, 1e18)` intending 100% but the bound is 0.9e18. With no check, the write succeeds. Borrowers immediately take loans at 100% LTV; any oracle flicker puts them underwater with zero liquidation incentive (liquidator's bonus comes out of the same now-worthless collateral), protocol eats the shortfall."
    WIKI_RECOMMENDATION = "Enforce `newCF <= collateralFactorMaxMantissa` in every CF setter. Reproduce Certora's `collateralFactorBounded` invariant as a unit test that fuzzes every admin path. Governance should also time-lock any CF raise above e.g. 0.8e18."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(Comptroller|cToken|CToken|Market|markets\\s*\\[|collateralFactorMantissa|collateralFactorMaxMantissa|_supportMarket|compound)'}, {'contract.has_state_var_matching': '(?i)(collateralFactor|ltv|collateralFactorMantissa)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(_setCollateralFactor|setCollateralFactor|setMarket|_supportMarket|configureMarket|updateMarket|setCollateralFactorMantissa)\\w*$'}, {'function.body_contains_regex': '(?i)(collateralFactor|_collateralFactor).*='}, {'function.body_not_contains_regex': '(?i)(collateralFactorMax|MAX_COLLATERAL|0\\.9e18|9e17|require[^;]*collateralFactor.*<=|collateralFactor\\s*<=\\s*[A-Z_])'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|_setCollateralFactorInternal\\s*\\(|onlyBoundChecked|_checkCollateralFactorBound)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-compound-collateral-factor-bounded: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
