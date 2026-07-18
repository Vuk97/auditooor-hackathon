"""
ltv-zero-asset-withdraw-blocked — generated from reference/patterns.dsl/ltv-zero-asset-withdraw-blocked.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ltv-zero-asset-withdraw-blocked.yaml
Source: C0006
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LtvZeroAssetWithdrawBlocked(AbstractDetector):
    ARGUMENT = "ltv-zero-asset-withdraw-blocked"
    HELP = "Lending integrator reads LTV from the underlying pool without a zero-LTV guard. When the underlying protocol disables an asset as collateral (LTV -> 0), withdraw/borrow/liquidate paths panic or diverge from the upstream health-factor math."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ltv-zero-asset-withdraw-blocked.yaml"
    WIKI_TITLE = "LTV = 0 asset makes withdraw / borrow / liquidate unreachable"
    WIKI_DESCRIPTION = "Aave (v2 and v3) and similar Compound-style lending pools allow governance to turn an asset OFF as collateral by setting its LTV to zero. Aave's core HF formula special-cases this: when LTV == 0 the asset contributes zero weighted collateral but the remaining solvency check still resolves. Integrators that copy the health-factor calculation without the zero-LTV branch will either (a) divide by zer"
    WIKI_EXPLOIT_SCENARIO = "1) A lending integrator (Morpho-style) mirrors Aave's reserve configuration for accounting. 2) Aave governance turns off asset X as collateral — `reserveConfig.ltv` becomes 0. 3) A user with any position that touches asset X calls `withdraw` / `borrow` / a liquidator calls `liquidate`. 4) The integrator's local HF path reads `ltv` and either divides by it, multiplies user collateral by 0 (producin"
    WIKI_RECOMMENDATION = "Before using an LTV value in health-factor math, branch on `ltv == 0`: treat the asset as providing zero collateral weight BUT continue with the remaining solvency check rather than reverting. Mirror Aave's own handling in `GenericLogic.calculateUserAccountData` — an LTV of 0 must NOT cause a divide"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pool|aave|comet|lendingPool|assetConfig'}, {'contract.has_function_matching': 'healthFactor|calcHF|_computeHF|healthCheck'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'withdraw|borrow|liquidate|_checkHealth'}, {'function.body_contains_regex': 'ltv|LTV|getLTV|reserveConfig|getReserveData'}, {'function.body_not_contains_regex': 'if\\s*\\(.*(ltv|LTV)\\s*==\\s*0|require\\s*\\(.*(ltv|LTV)\\s*!=\\s*0|ltv\\s*>\\s*0'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ltv-zero-asset-withdraw-blocked: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
