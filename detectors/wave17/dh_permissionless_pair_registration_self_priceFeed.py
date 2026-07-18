"""
dh-permissionless-pair-registration-self-priceFeed — generated from reference/patterns.dsl/dh-permissionless-pair-registration-self-priceFeed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-permissionless-pair-registration-self-priceFeed.yaml
Source: defihacklabs-2024-05/PredyFinance
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhPermissionlessPairRegistrationSelfPricefeed(AbstractDetector):
    ARGUMENT = "dh-permissionless-pair-registration-self-priceFeed"
    HELP = "Permissionless market/pair-registration entrypoint lets the caller nominate an attacker-controlled priceFeed / poolOwner. Subsequent trades against that pair use the attacker's oracle, letting them drain shared liquidity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-permissionless-pair-registration-self-priceFeed.yaml"
    WIKI_TITLE = "Permissionless pair registration with caller-controlled oracle"
    WIKI_DESCRIPTION = "A perp/vault factory exposes an un-gated `registerPair(..)` (or `createPair` / `addMarket`) that stores a caller-supplied `priceFeed` and `poolOwner` address. Any caller can register a new pair and point the oracle at themselves. Because the factory's shared liquidity or token-level approvals flow through the same pool contract, the attacker-registered pair can be used to price trades at arbitrary"
    WIKI_EXPLOIT_SCENARIO = "PredyFinance (May 2024, $464K on Arbitrum): attacker called `registerPair` with `priceFeed = address(this)` and `poolOwner = address(this)`. The attacker's `getSqrtPrice()` returned 40e9, enabling a self-priced `trade()` loop. Inside `predyTradeAfterCallback` the attacker supplied + took shares to bypass solvency, then withdrew all pool liquidity."
    WIKI_RECOMMENDATION = "Gate market/pair registration behind governance or an owner-approved whitelist of oracle sources. If registration must be permissionless, require the supplied `priceFeed` to come from a trusted registry (Chainlink / approved adapter list) and validate the `poolOwner` — never let callers become both "

    _PRECONDITIONS = [{'contract.source_matches_regex': 'registerPair|createPair|addPair|addPool|addMarket|registerMarket'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(registerPair|createPair|addPair|addPool|addMarket|registerMarket|addCollateralVault)$'}, {'function.body_contains_regex': '\\.(priceFeed|poolOwner|oracle|priceSource|strategy)\\b|priceFeed\\s*[:=]|poolOwner\\s*[:=]'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRole', 'onlyRoles', 'onlyGovernance', 'onlyGov', 'onlyTimelock', 'onlyManager', 'whenNotPaused'], 'negate': True}}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-permissionless-pair-registration-self-priceFeed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
