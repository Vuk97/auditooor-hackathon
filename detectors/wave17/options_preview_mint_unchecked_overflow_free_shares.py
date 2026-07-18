"""
options-preview-mint-unchecked-overflow-free-shares — generated from reference/patterns.dsl/options-preview-mint-unchecked-overflow-free-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py options-preview-mint-unchecked-overflow-free-shares.yaml
Source: auditooor-R75-c4-2024-04-panoptic-H438
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OptionsPreviewMintUncheckedOverflowFreeShares(AbstractDetector):
    ARGUMENT = "options-preview-mint-unchecked-overflow-free-shares"
    HELP = "`previewMint` computes `shares * DECIMALS` inside `unchecked` with no upper-bound check on `shares`. Picking `shares = type(uint256).max / DECIMALS + 1` overflows the multiplication; downstream `mulDiv` returns `assets = 1` (or similar tiny number). Attacker pays 1 wei for huge share minting and dra"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/options-preview-mint-unchecked-overflow-free-shares.yaml"
    WIKI_TITLE = "ERC4626 collateral tracker: unchecked `shares * DECIMALS` overflow mints shares for ~free"
    WIKI_DESCRIPTION = "Many options/perps vaults wrap an ERC4626-like deposit interface where `mint(shares)` asks the user for however many underlying assets back the requested shares. The inner `previewMint(shares)` runs `Math.mulDivRoundingUp(shares * DECIMALS, totalAssets, totalSupply * (DECIMALS - COMMISSION_FEE))` and that whole block is `unchecked`. The `shares * DECIMALS` multiplication is the attacker's lever: c"
    WIKI_EXPLOIT_SCENARIO = "(1) Vault has 10M USDC TVL, 10M shares, `DECIMALS = 10000`, `COMMISSION_FEE = 60`. (2) Bob picks `shares = type(uint256).max / 10000 + 1`. Inside `unchecked`, `shares * DECIMALS` overflows to 10000 (the +1). (3) `assets = mulDivRoundingUp(10000, 10M*1e6, 10M * 9940) ≈ 1 USDC`. (4) Check `assets > type(uint104).max` passes (assets is 1). (5) Bob approves 1 USDC, calls `mint(shares, bob)`. His share"
    WIKI_RECOMMENDATION = "Enforce an upper bound BEFORE the multiplication: `require(shares <= type(uint128).max, DepositTooLarge())` or `require(shares <= maxMint(receiver), DepositTooLarge())`. Alternatively, remove the `unchecked` block so Solidity 0.8+ reverts on the overflow naturally. Add a fuzz/invariant: after `mint("

    _PRECONDITIONS = [{'contract.source_matches_regex': '(previewMint|previewDeposit|mint|CollateralTracker)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.state_mutability': 'view'}, {'function.name_matches': '(previewMint|_previewMint|previewDeposit)'}, {'function.body_contains_regex': 'unchecked\\s*\\{[\\s\\S]{0,600}(shares|_shares|input)\\s*\\*\\s*(DECIMALS|1e|10\\s*\\*\\*|_decimals)'}, {'function.body_contains_regex': '(mulDiv|mulDivRoundingUp|divWadUp|muldiv)'}, {'function.body_not_contains_regex': '(shares\\s*<=?\\s*maxShares|shares\\s*<=?\\s*maxMint|require\\s*\\([^)]*shares[^)]*max|type\\(uint(104|128)\\)\\.max)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — options-preview-mint-unchecked-overflow-free-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
