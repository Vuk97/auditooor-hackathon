"""
certora-aave-ltv-bounded-by-liquidation-threshold — generated from reference/patterns.dsl/certora-aave-ltv-bounded-by-liquidation-threshold.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-aave-ltv-bounded-by-liquidation-threshold.yaml
Source: certora-aave-v3-core/PoolConfigurator/ltvLeLiquidationThreshold
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraAaveLtvBoundedByLiquidationThreshold(AbstractDetector):
    ARGUMENT = "certora-aave-ltv-bounded-by-liquidation-threshold"
    HELP = "LTV or liquidation threshold setter does not enforce `ltv <= liquidationThreshold` — breaks Certora `ltvLeLiquidationThreshold` invariant."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-aave-ltv-bounded-by-liquidation-threshold.yaml"
    WIKI_TITLE = "LTV setter lacks `ltv <= liquidationThreshold` bound check"
    WIKI_DESCRIPTION = "Aave's Certora spec on `PoolConfigurator`/`ReserveConfiguration` proves that for every reserve, LTV is at most the liquidation threshold (otherwise a healthy position could be born already liquidatable). A setter that mutates LTV or LT without re-asserting the bound admits a mis-configuration: user borrows to LTV = 80% while LT = 70% — the user is immediately liquidatable on position open, a liqui"
    WIKI_EXPLOIT_SCENARIO = "A governance proposal calls `setLtv(asset, 8500)` on a reserve with `liquidationThreshold = 8000`. The setter only validates `ltv <= 9999` individually, not the cross-field bound. Users open 85% LTV positions. Oracles dip 1%, users are instantly liquidatable while protocol accepted fresh borrow — liquidators drain the new reserve, protocol books bad debt on the freshly-opened positions."
    WIKI_RECOMMENDATION = "Every reserve-parameter setter must enforce the full Aave invariant set: `ltv <= liquidationThreshold <= 1e4`, `liquidationBonus > 1e4`, and `ltv > 0 => liquidationThreshold > 0`. Run the Certora `ltvLeLiquidationThreshold` rule on every param-change path."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(PoolConfigurator|ReserveConfiguration|ReserveConfig|collateralConfig|configureReserve|CollateralConfiguration|liquidationThreshold|loanToValue|LTV|EMode)'}, {'contract.has_state_var_matching': '(?i)(ltv|loanToValue|liquidationThreshold|lt|_lt|_ltv|liqThreshold)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(setLtv|setLoanToValue|setLiquidationThreshold|configureReserveAsCollateral|setReserveParams|setCollateralConfig|updateReserve|setEMode|configureEMode|setEModeCategory)\\w*$'}, {'function.body_contains_regex': '(?i)(ltv|loanToValue|liquidationThreshold|_lt|_ltv)\\s*='}, {'function.body_not_contains_regex': '(?i)(ltv\\s*<=\\s*.*(liquidationThreshold|lt)|(liquidationThreshold|lt)\\s*>=\\s*ltv|require\\s*\\([^)]*ltv[^)]*(liquidationThreshold|lt))'}, {'function.not_source_matches_regex': '(?i)(view\\s+returns|pure\\s+returns|_packConfiguration|configuration\\.data\\s*=\\s*\\(|PercentageMath\\.percentMul|uint256\\s+constant\\s+MAX_VALID)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-aave-ltv-bounded-by-liquidation-threshold: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
