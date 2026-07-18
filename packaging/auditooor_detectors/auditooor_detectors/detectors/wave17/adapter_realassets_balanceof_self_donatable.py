"""
adapter-realassets-balanceof-self-donatable — generated from reference/patterns.dsl/adapter-realassets-balanceof-self-donatable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py adapter-realassets-balanceof-self-donatable.yaml
Source: auditooor-R101-morpho-CS-VLT2-020
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdapterRealassetsBalanceofSelfDonatable(AbstractDetector):
    ARGUMENT = "adapter-realassets-balanceof-self-donatable"
    HELP = "Vault adapter's `realAssets()` view derives the adapter's reported asset count from `IERC4626(underlying).balanceOf(address(this))` (or `IERC20.balanceOf(self)`) and feeds it into `previewRedeem`. Anyone can `transfer` shares to the adapter; the next accrual reads the inflated balance and treats the"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/adapter-realassets-balanceof-self-donatable.yaml"
    WIKI_TITLE = "Adapter `realAssets()` reads `balanceOf(address(this))` — donations directly inflate share price"
    WIKI_DESCRIPTION = "ERC-4626-style vault adapters that report their assets to the parent vault via `realAssets()` (or `totalAssets()`) have a fork in design: read shares LIVE from the underlying protocol (`previewRedeem(IERC4626(u).balanceOf(address(this)))`) versus track shares in an internal mapping (`supplyShares[market]`). The first form is implicitly donation-vulnerable: any address can `IERC20(u).transfer(adapt"
    WIKI_EXPLOIT_SCENARIO = "Vault has 3 adapters; adapter A2 reports its assets via `realAssets() => previewRedeem(metaMorpho.balanceOf(address(this)))`. Attacker borrows $1M of metaMorpho shares (or buys outright), sends them to A2 with `metaMorpho.transfer(a2, $1M_shares)`. Block N+1 vault accrual fires, `accrueInterestView()` sees A2.realAssets = previous + $1M, vault `_totalAssets` rises by $1M (capped at `maxRate` over "
    WIKI_RECOMMENDATION = "Replace the live balance read with internal share-tracking: maintain `mapping(bytes32 => uint256) supplyShares` (or per-market / per-position equivalent), increment on `allocate(...)` after the underlying call returns the actual minted-shares value, decrement on `deallocate(...)`, and have `realAsse"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Adapter|Strategy|Wrapper|Allocator'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?realAssets|_?totalAssets|_?assets|_?expectedAssets|_?expectedSupplyAssets|_?underlyingAssets)$'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|balanceOf\\s*\\(\\s*self\\s*\\)'}, {'function.body_contains_regex': 'previewRedeem|previewWithdraw|convertToAssets|expectedSupplyAssets|exchangeRate'}, {'function.body_not_contains_regex': '\\bsupplyShares\\s*\\[|\\binternalShares\\s*\\[|\\btrackedShares\\s*\\[|\\bownedShares\\s*\\[|\\bsharesAccounting\\s*\\['}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — adapter-realassets-balanceof-self-donatable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
