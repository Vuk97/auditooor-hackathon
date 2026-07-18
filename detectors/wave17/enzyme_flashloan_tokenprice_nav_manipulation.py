"""
enzyme-flashloan-tokenprice-nav-manipulation — generated from reference/patterns.dsl/enzyme-flashloan-tokenprice-nav-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py enzyme-flashloan-tokenprice-nav-manipulation.yaml
Source: auditooor-R76-immunefi-enzyme-$200k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EnzymeFlashloanTokenpriceNavManipulation(AbstractDetector):
    ARGUMENT = "enzyme-flashloan-tokenprice-nav-manipulation"
    HELP = "Price-feed adapter computes share price from the underlying integration's LIVE balance/totalSupply. If the underlying protocol later adds flashloans, the adapter becomes flashloan-manipulable without any adapter code change."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/enzyme-flashloan-tokenprice-nav-manipulation.yaml"
    WIKI_TITLE = "Upgradeable-integration price feed becomes manipulable when integrated token adds flashloans"
    WIKI_DESCRIPTION = "Price-feed adapters that compute `sharePrice = NAV / totalSupply` from live on-chain storage inherit every new primitive the underlying protocol ships. If the integration is upgradeable (or its authors deploy a new version at the same address), a later release can introduce flashloans or pause-able NAV that the adapter never expected. Inside a single transaction the attacker flashloans out NAV, th"
    WIKI_EXPLOIT_SCENARIO = "Enzyme's IdlePriceFeed integrated IdleToken v4 which had no flashloan. Idle later upgraded to v5 adding flashloans. Attacker: flashloan Idle vault → WETH→USDC swap → call Enzyme.buyShares (cheap price from manipulated NAV) → repay flashloan → redeemShares at normal price. $200k bounty; Idle delisted."
    WIKI_RECOMMENDATION = "Price feeds for upgradeable integrations MUST use an external oracle (Chainlink, TWAP) or a snapshot-taken-at-a-previous-block reading. If live-read is unavoidable, assert the integrated contract's bytecode hash matches a pinned audit version. Subscribe to the integrated protocol's upgrade events an"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_price_feed_adapter': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)tokenPrice|getUnderlyingAmount|calcUnderlying|pricePerShare|getRate'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)\\.tokenPrice\\s*\\(\\)|\\.getNAV|\\.balanceOf\\s*\\(\\s*address\\(this\\)\\s*\\)\\s*/\\s*\\.totalSupply|IIdleToken|cToken\\.exchangeRateStored'}, {'function.body_not_contains_regex': '(?i)oracle\\.latestAnswer|chainlink|twap|observationCardinality|snapshotBlock|flashloanGuard|_isInFlashLoan'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — enzyme-flashloan-tokenprice-nav-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
