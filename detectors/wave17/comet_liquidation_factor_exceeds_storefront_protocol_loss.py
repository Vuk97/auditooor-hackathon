"""
comet-liquidation-factor-exceeds-storefront-protocol-loss — generated from reference/patterns.dsl/comet-liquidation-factor-exceeds-storefront-protocol-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-liquidation-factor-exceeds-storefront-protocol-loss.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-3ce8a07d1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometLiquidationFactorExceedsStorefrontProtocolLoss(AbstractDetector):
    ARGUMENT = "comet-liquidation-factor-exceeds-storefront-protocol-loss"
    HELP = "Asset configuration path sets both `liquidationFactor` and `storeFrontPriceFactor` without asserting `liquidationFactor <= storeFrontPriceFactor`. When the storefront discount exceeds the liquidation penalty, buyers purchase seized collateral below the value at which the protocol recognised the debt"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-liquidation-factor-exceeds-storefront-protocol-loss.yaml"
    WIKI_TITLE = "Missing invariant: liquidationFactor must not exceed storeFrontPriceFactor"
    WIKI_DESCRIPTION = "In a Comet-style market the liquidation penalty is `(1 - liquidationFactor)` of the seized collateral value — this is how much the protocol believes it is 'winning' per liquidation. The storefront discount is `(1 - storeFrontPriceFactor)` (or, in later designs, `storeFrontPriceFactor * (1 - liquidationFactor)`) — how much the collateral buyer pays below market. If `storeFrontPriceFactor < liquidat"
    WIKI_EXPLOIT_SCENARIO = "Governance (or a mis-configured deployment script — see the `NetworkConfiguration.ts` bug in commit 3ce8a07d14 where `storeFrontPriceFactor` was not correctly converted into a percentage) sets `liquidationFactor = 0.95e18` and `storeFrontPriceFactor = 0.80e18`. Protocol believes liquidation penalty is 5%. An absorption triggers: collateral worth $100 is seized. Storefront sells it for `$100 * 0.80"
    WIKI_RECOMMENDATION = "In the `initialize` / `setConfiguration` / `addAsset` path, after all other asset-config sanity checks, add: `if (assetConfig.liquidationFactor > storeFrontPriceFactor) revert BadLiquidationFactor();`. Because both factors may be updated independently, also enforce the invariant in any setter that m"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'liquidationFactor|liquidateCollateralFactor|storeFrontPriceFactor|discountFactor'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(initialize|_initialize|setConfiguration|setAssetConfig|addAsset|updateAssetConfig|constructor)$'}, {'function.body_contains_regex': 'liquidationFactor|liquidateCollateralFactor'}, {'function.body_contains_regex': 'storeFrontPriceFactor|storefrontPriceFactor'}, {'function.body_not_contains_regex': 'liquidationFactor\\s*>\\s*storeFrontPriceFactor|liquidationFactor\\s*>\\s*storefrontPriceFactor|liquidationFactor\\s*\\+\\s*storeFrontPriceFactor|FACTOR_SCALE\\s*-\\s*liquidationFactor'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-liquidation-factor-exceeds-storefront-protocol-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
