"""
vault-0x8d2e-style-price-manipulation — generated from reference/patterns.dsl/vault-0x8d2e-style-price-manipulation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-0x8d2e-style-price-manipulation.yaml
Source: solodit-cluster/C0007
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Vault0x8d2eStylePriceManipulation(AbstractDetector):
    ARGUMENT = "vault-0x8d2e-style-price-manipulation"
    HELP = "Vault preview/totalAssets/convertTo accessor reads balanceOf(address(this)) as canonical reserves with no tracked-ledger defense — attacker inflates balance via direct transfer and steals share-price delta (0x8d2e / UsualMoney / unverified_8490 2025 exploits)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-0x8d2e-style-price-manipulation.yaml"
    WIKI_TITLE = "Vault share-price manipulation via balanceOf(self) donation attack (0x8d2e / UsualMoney 2025)"
    WIKI_DESCRIPTION = "The vault's previewWithdraw / previewRedeem / totalAssets / convertTo* accessor reads `balanceOf(address(this))` as the source of truth for the asset reserves backing shares. Because ERC20 `transfer` lets anyone push tokens directly into the contract without calling deposit, an attacker can inflate the reading by donating underlying, desyncing it from the internal share ledger. The vault's share m"
    WIKI_EXPLOIT_SCENARIO = "A vault holds 100 DAI of user deposits with totalSupply=100 shares. Attacker direct-transfers 900 DAI to the vault's address. The vault's `totalAssets() { return asset.balanceOf(address(this)); }` now returns 1,000 DAI. A depositor arrives with 100 DAI expecting ~100 shares (10% of supply). The vault computes `shares = 100 * 100 / 1000 = 10` — the depositor receives 10 shares for 100 DAI. The atta"
    WIKI_RECOMMENDATION = "Do not source totalAssets from balanceOf(address(this)). Maintain an internal `trackedAssets` / `storedReserves` state variable that is incremented on deposit and decremented on withdrawal, and use that as the canonical asset figure for all share math. As a defense-in-depth, add a `skim` / `sync` fu"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'totalAssets|totalShares|totalSupply'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'totalAssets|previewRedeem|previewWithdraw|convertToAssets|convertToShares|_totalAssets|sharePrice|pricePerShare'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)|balanceOf\\s*\\(\\s*self\\s*\\)|asset\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)'}, {'function.body_not_contains_regex': 'trackedAssets|_trackedBalance|virtualBalance|snapshotReserves|storedReserves'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-0x8d2e-style-price-manipulation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
