"""
redemption-uses-asset-oracle-instead-of-peg-price — generated from reference/patterns.dsl/redemption-uses-asset-oracle-instead-of-peg-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py redemption-uses-asset-oracle-instead-of-peg-price.yaml
Source: auditooor-R75-c4-lending-dittoeth-275
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RedemptionUsesAssetOracleInsteadOfPegPrice(AbstractDetector):
    ARGUMENT = "redemption-uses-asset-oracle-instead-of-peg-price"
    HELP = "Redemption converts stablecoin → collateral using oracle(stablecoin) as the rate. Should use the intended peg (or oracle(collateral)/USD). Breaks peg-restoring arbitrage when stable is off-peg."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/redemption-uses-asset-oracle-instead-of-peg-price.yaml"
    WIKI_TITLE = "Redemption prices stablecoin at market, not at peg"
    WIKI_DESCRIPTION = "A CDP/stablecoin protocol's redemption lets holders swap stablecoin for collateral at the rate 1 stable ≈ $1 worth of collateral — this is the arbitrage that pulls the stable back to $1. Correct conversion uses `collateralAmount = stableAmount * $1 / oracle(collateral_USD)`. Bug: code calls `oracle(stable)` instead of the hardcoded peg (or of `oracle(collateral)`). If stable trades at $0.90, redee"
    WIKI_EXPLOIT_SCENARIO = "dUSD is a USD-pegged stable against ETH. Redemption should give `amount * 1 USD / ETH_USD` worth of ETH per 1 dUSD. Instead it computes `amount * dUSD_USD / 1 USD`, i.e. `amount * 0.90` worth of ETH when dUSD trades at $0.90. Arb traders have no reason to redeem — they would get the same ETH by selling dUSD on the market. dUSD's depeg is permanent; protocol accrues bad debt as CR thresholds leak."
    WIKI_RECOMMENDATION = "Hardcode the peg in the redemption path: `collateralAmount = (stableAmount * PEG_PRECISION) / oracle(collateralAsset)`. Never read the stablecoin's market oracle inside its own redemption. If the protocol uses a proxy for USD (e.g. ETH/USD Chainlink), price the COLLATERAL in USD, not the debt token."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(?i)(getPrice|latestAnswer|latestResolver|getOraclePrice)\\s*\\(\\s*(asset|stable|_asset|debtToken|dUSD)\\b'}, {'function.body_not_contains_regex': '(?i)(PEG|\\bONE_USD\\b|assumePeg|USD_PEG)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — redemption-uses-asset-oracle-instead-of-peg-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
