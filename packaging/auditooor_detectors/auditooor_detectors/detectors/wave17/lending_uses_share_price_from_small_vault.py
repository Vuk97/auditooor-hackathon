"""
lending-uses-share-price-from-small-vault — generated from reference/patterns.dsl/lending-uses-share-price-from-small-vault.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lending-uses-share-price-from-small-vault.yaml
Source: defihacklabs/2025-06-ResupplyFi
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LendingUsesSharePriceFromSmallVault(AbstractDetector):
    ARGUMENT = "lending-uses-share-price-from-small-vault"
    HELP = "Lending/collateral pricing reads `vault.convertToAssets()` / `pricePerShare()` without asserting the vault has a minimum totalSupply, enabling the classic small-supply price manipulation that lets 1 wei of shares back a large loan."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lending-uses-share-price-from-small-vault.yaml"
    WIKI_TITLE = "Collateral price sourced from ERC4626 vault without supply floor"
    WIKI_DESCRIPTION = "If a lending market prices collateral as `shares * vault.convertToAssets(1e18)` (or equivalent), and the underlying vault has very small totalSupply, an attacker can donate the underlying directly to the vault, inflating price-per-share. The attacker deposits 1 wei of shares as collateral and borrows against an inflated valuation, draining the market."
    WIKI_EXPLOIT_SCENARIO = "ResupplyFi (Jun 2025, $9.6M): sCrvUsd vault had tiny totalSupply relative to a donated amount. Attacker flash-loaned USDC, donated crvUSD to sCrvUsd, minted 1 wei of shares, added those shares as collateral to ResupplyVault, and borrowed 10M reUSD — because the lending contract read sCrvUsd.convertToAssets() and saw ~10M assets backing 1 wei of shares."
    WIKI_RECOMMENDATION = "Either (a) require `vault.totalSupply() >= MIN_SHARE_SUPPLY` before pricing, (b) use a TWAP of share price (ERC4626 observation oracle), or (c) only allow-list vaults whose deposits are gated through a trusted onboarding path that pre-mints dead shares."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(borrow|collateral|ltv|convertToAssets|pricePerShare|getSharePrice)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(borrow|_borrow|calcCollateral|getCollateralValue|_getCollateralValue)'}, {'function.body_contains_regex': 'convertToAssets\\s*\\(|pricePerShare\\s*\\(|getSharePrice\\s*\\(|exchangeRate\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*totalSupply\\s*>=|totalSupply\\s*\\(\\s*\\)\\s*>\\s*\\d{4,}|MIN_SHARE_SUPPLY'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lending-uses-share-price-from-small-vault: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
