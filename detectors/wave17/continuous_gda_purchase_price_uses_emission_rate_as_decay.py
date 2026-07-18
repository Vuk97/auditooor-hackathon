"""
continuous-gda-purchase-price-uses-emission-rate-as-decay — generated from reference/patterns.dsl/continuous-gda-purchase-price-uses-emission-rate-as-decay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py continuous-gda-purchase-price-uses-emission-rate-as-decay.yaml
Source: lisa-mine-r99-case-05981-c4-pooltogether-cgda-liquidator-2023-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ContinuousGdaPurchasePriceUsesEmissionRateAsDecay(AbstractDetector):
    ARGUMENT = "continuous-gda-purchase-price-uses-emission-rate-as-decay"
    HELP = "ContinuousGDA `purchasePrice` formula multiplies time elapsed by `_emissionRate` where the standard CGDA formula uses `_decayConstant`. The two have different units and different expected magnitudes — emission rate is in tokens/second, decay constant is in inverse-seconds. Substituting one for the o"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/continuous-gda-purchase-price-uses-emission-rate-as-decay.yaml"
    WIKI_TITLE = "ContinuousGDA purchasePrice multiplies time by emissionRate instead of decayConstant"
    WIKI_DESCRIPTION = "Pattern fires on Continuous-GDA `purchasePrice` (or equivalent) helpers whose body uses `_emissionRate` in the exponential decay term where the canonical formula calls for `_decayConstant`. The CGDA pricing function is `p(t) = (k / r) * (e^(r*q) - 1) / e^(d*t)` where `r = emissionRate`, `d = decayConstant`. The bug substitutes `r` for `d` in the denominator's exp argument."
    WIKI_EXPLOIT_SCENARIO = "PoolTogether CGDA-liquidator quotes liquidator buy prices that decay too quickly (or too slowly, depending on the relative magnitudes). Liquidators front-run yield distributions when prices are below market, extracting yield at a discount the protocol never priced for. Across many epochs, this transfers a large fraction of yield from PoolTogether stakers to liquidator MEV bots."
    WIKI_RECOMMENDATION = "Audit the formula against the original VRGDA / CGDA paper. The decay term in the denominator (`e^(-decayConstant * elapsed)`) must use the SAME constant as the rate at which the auction is intended to drift back to its target schedule, not the rate at which yield is emitted. Add a property test fuzz"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ContinuousGDA|GradualDutchAuction|gdaPurchasePrice|emissionRate|decayConstant'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'purchasePrice|gdaPurchasePrice|computePurchasePrice|priceForQuantity|currentPrice'}, {'function.body_contains_regex': '\\b_emissionRate\\b|\\bemissionRate\\b'}, {'function.body_contains_regex': '\\.exp\\s*\\(|exp\\s*\\('}, {'function.body_not_contains_regex': 'decayConstant\\s*\\.\\s*mul|decayConstant\\s*\\*|emissionRate\\s*\\*\\s*[A-Za-z_]*[Tt]ime|secondsSinceLastSale\\s*\\*\\s*decayConstant'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — continuous-gda-purchase-price-uses-emission-rate-as-decay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
