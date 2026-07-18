"""
oracle-uses-ytoken-pricepershare-without-totalsupply-sanity — generated from reference/patterns.dsl/oracle-uses-ytoken-pricepershare-without-totalsupply-sanity.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-uses-ytoken-pricepershare-without-totalsupply-sanity.yaml
Source: auditooor-R76-rekt-cream-finance-2021
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleUsesYtokenPricepershareWithoutTotalsupplySanity(AbstractDetector):
    ARGUMENT = "oracle-uses-ytoken-pricepershare-without-totalsupply-sanity"
    HELP = "Protocol oracle computes vault collateral price from instantaneous `vault.balance() / vault.totalSupply()` without a minimum-supply floor or TWAP. Flash-loan redeeming most of the supply then depositing a tiny amount inflates the price by ~2x."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-uses-ytoken-pricepershare-without-totalsupply-sanity.yaml"
    WIKI_TITLE = "Vault pricePerShare used as collateral oracle without min-supply guard or TWAP"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row matches oracle-shaped view functions that derive a yield-vault collateral price from spot `pricePerShare` or `vault.balance() / vault.totalSupply()` and omit any visible minimum-supply or smoothing guard. Cream Finance lost ~$130M in Oct 2021 to this pattern on yUSDVault, but this detector still needs broader corpus validation before promotion."
    WIKI_EXPLOIT_SCENARIO = "Attacker holds 500M yUSDVault (via flash loan). Calls `yVault.withdraw(500M)` — totalSupply drops to 8M, balance drops to ~8M: pricePerShare ≈ 1. Attacker deposits 8M yUSD: balance ≈ 16M, totalSupply ≈ 16M, pricePerShare ≈ 1 — but if the withdrawal had even 0.01% yield accrual, balance would be 16.2M against supply 16M, so pricePerShare = 1.0125. Repeated / stacked, attacker pushes the reported pr"
    WIKI_RECOMMENDATION = "Do not use spot `pricePerShare` as an oracle. Either: (a) use a Chainlink-style TWAP over >=30 min with deviation bands; (b) require `totalSupply >= minFloor` and revert otherwise; (c) cap the per-block change in reported price at e.g. 5%. For yield-bearing collateral, prefer reading the underlying "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(oracle|collateral|underlying|vault|yToken|yVault|getPricePerFullShare|pricePerShare)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(?i)getUnderlyingPrice|getPrice|latestAnswer|fetchPrice|getAssetPrice|_getPrice'}, {'function.body_contains_regex': '(?i)(getPricePerFullShare\\s*\\(|pricePerShare\\s*\\(|balance\\s*\\(\\s*\\)\\s*\\*\\s*[^;{}]{0,120}/\\s*[^;{}]{0,40}totalSupply\\s*\\(\\s*\\)|balanceOf\\([^)]*\\)\\s*\\*\\s*[^;{}]{0,120}/\\s*[^;{}]{0,40}totalSupply\\s*\\(\\s*\\))'}, {'function.body_contains_regex': '(?i)totalSupply\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': '(?i)(twap|consult|observe|chainlink|latestRoundData|priceOracle|ema|movingAverage|timeWeighted)'}, {'function.body_not_contains_regex': '(?i)((require|assert)\\s*\\([^;{}]{0,120}totalSupply\\s*\\(\\s*\\)\\s*(>=|>)|MIN(_| )?(SHARE_)?SUPPLY|min(Supply|Shares|ShareSupply)|supplyFloor|minFloor|sanityBand|deviationBand|maxPriceChange)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-uses-ytoken-pricepershare-without-totalsupply-sanity: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
