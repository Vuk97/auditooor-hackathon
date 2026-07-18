"""
r74-oracle-liquidation-factor-above-storefront — generated from reference/patterns.dsl/r74-oracle-liquidation-factor-above-storefront.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-oracle-liquidation-factor-above-storefront.yaml
Source: r74b-cross-firm-cs+tob
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74OracleLiquidationFactorAboveStorefront(AbstractDetector):
    ARGUMENT = "r74-oracle-liquidation-factor-above-storefront"
    HELP = "Setter for liquidationFactor/storeFrontPriceFactor lacks cross-check that liquidationFactor < storeFrontPriceFactor. Misconfiguration bleeds value to liquidators on every liquidation."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-oracle-liquidation-factor-above-storefront.yaml"
    WIKI_TITLE = "Liquidation-factor setter missing sanity bound against store-front-price-factor"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. In Compound-Comet-style liquidation designs, the protocol loses money on each liquidation when the borrower's liquidation penalty is smaller than the discount offered to the liquidator buying collateral. Any setter that writes these factors independently must also enforce the invariant liquidationFactor < storeFrontPriceFactor (or equivalent"
    WIKI_EXPLOIT_SCENARIO = "Governance sets liquidationFactor = 0.95 and storeFrontPriceFactor = 0.97 via independent transactions. The contract accepts both. On the next significant price drop, a liquidator buys collateral at 97% of oracle price while borrowers only pay 95% penalty — the protocol absorbs the 2% delta on every liquidation until governance notices."
    WIKI_RECOMMENDATION = "In every setter that touches any of {liquidationFactor, liquidationPenalty, storeFrontPriceFactor, liquidationIncentive}, add a require asserting liquidationFactor < storeFrontPriceFactor (after applying both proposed values). Prefer a single atomic `setFactors(...)` that rejects internally inconsis"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(liquidationFactor|storeFrontPriceFactor|liquidationPenalty|liquidationIncentive|closeFactor)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(set|update|configure|_setAsset|_getPackedAsset)[A-Za-z0-9_]*(liquidation|storefront|penalty|incentive|closefactor)'}, {'function.is_mutating': True}, {'function.body_not_contains_regex': 'require\\s*\\([^)]*(liquidationFactor|liquidationPenalty|liquidationIncentive)[^)]*(storeFront|storefront|discount|bonus)|require\\s*\\([^)]*<\\s*(storeFront|storefront|discount)|assert\\s*\\([^)]*(liquidation).*<'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-oracle-liquidation-factor-above-storefront: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
