"""
erc4626-oracle-uses-vault-decimals-not-asset-decimals — generated from reference/patterns.dsl/erc4626-oracle-uses-vault-decimals-not-asset-decimals.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-oracle-uses-vault-decimals-not-asset-decimals.yaml
Source: lisa-mine-r99-case-03022-sherlock-sentiment-2023-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626OracleUsesVaultDecimalsNotAssetDecimals(AbstractDetector):
    ARGUMENT = "erc4626-oracle-uses-vault-decimals-not-asset-decimals"
    HELP = "ERC-4626 oracle reads `IERC4626(vault).decimals()` and uses it as the share decimals AND the underlying-asset decimals at the same time, calling `previewRedeem(10 ** vaultDecimals)` to get a 'price per share' and multiplying by the underlying-asset USD price. EIP-4626 explicitly allows the vault's d"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-oracle-uses-vault-decimals-not-asset-decimals.yaml"
    WIKI_TITLE = "ERC-4626 oracle uses vault decimals where underlying-asset decimals are required"
    WIKI_DESCRIPTION = "Pattern fires on `getPrice`-style oracle adapters for ERC-4626 vaults that compute `pricePerShare = previewRedeem(10**vaultDecimals)` and then multiply by the underlying-asset's USD price. EIP-4626's `decimals()` SHOULD reflect the share token's decimals, but the function the oracle is approximating is `(USD_per_asset_unit) * (asset_units_per_share)`. The asset-units-per-share quantity must be com"
    WIKI_EXPLOIT_SCENARIO = "Sentiment lists an ERC-4626 vault wrapping USDC (6 decimals) with the wrapper using 18 decimals (Solmate / OZ default). `getPrice(vault)` returns ~10^12 × the actual price. Sentiment's risk engine treats a $1000 deposit as $10^15, allowing the user to borrow far beyond their real collateral. The user opens a max-leverage position, withdraws the borrow, then defaults — protocol absorbs the loss. Th"
    WIKI_RECOMMENDATION = "Fetch BOTH decimals: `uint8 vaultDec = vault.decimals(); uint8 assetDec = IERC20(vault.asset()).decimals();`. Compute `assetsPerShare = previewRedeem(10**vaultDec)` (this gives `assetUnits` per share in underlying's smallest unit, which is correct). Then scale to a common 1e18 base when feeding into"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IERC4626|ERC4626|previewRedeem|previewMint|previewDeposit|previewWithdraw'}, {'contract.has_function_matching': 'getPrice|priceOf|fetchPrice|valueOf'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(getPrice|priceOf|valueOf|_getPrice)$'}, {'function.body_contains_regex': 'IERC4626\\s*\\(\\s*[A-Za-z_]\\w*\\s*\\)\\s*\\.\\s*decimals\\s*\\(\\s*\\)|previewRedeem\\s*\\(\\s*10\\s*\\*\\*\\s*decimals'}, {'function.body_not_contains_regex': '\\.asset\\s*\\(\\s*\\)\\s*\\)\\s*\\.\\s*decimals|asset\\s*\\(\\s*\\)\\s*\\.\\s*decimals|underlyingDecimals|assetDecimals\\s*=|10\\s*\\*\\*\\s*assetDec|10\\s*\\*\\*\\s*underlyingDecimals|assertDecimalsMatch'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-oracle-uses-vault-decimals-not-asset-decimals: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
