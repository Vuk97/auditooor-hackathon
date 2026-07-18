"""
self-liquidation-same-collateral-borrow-asset — generated from reference/patterns.dsl/self-liquidation-same-collateral-borrow-asset.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py self-liquidation-same-collateral-borrow-asset.yaml
Source: defihacklabs/AlkemiEarn_2026-03
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SelfLiquidationSameCollateralBorrowAsset(AbstractDetector):
    ARGUMENT = "self-liquidation-same-collateral-borrow-asset"
    HELP = "A Compound-fork `liquidateBorrow(borrower, repayAmt, borrowedAsset, collateralAsset)` accepts `collateralAsset == borrowedAsset`. Attacker flash-loans the asset, supplies it as collateral, borrows the same asset, then liquidates themselves to capture the liquidation bonus with zero net principal at "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/self-liquidation-same-collateral-borrow-asset.yaml"
    WIKI_TITLE = "Liquidation allows collateral asset == borrowed asset (self-liquidation bonus farm)"
    WIKI_DESCRIPTION = "A Compound-family lending market exposes `liquidateBorrow(borrower, repayAmount, borrowedAsset, collateralAsset)` but never checks that the two asset arguments differ. When they are the same token, the liquidation math degenerates: the liquidator both pays AND receives the same ERC-20, but the protocol still applies the liquidation bonus on the collateral leg. An attacker flash-loans the asset, su"
    WIKI_EXPLOIT_SCENARIO = "AlkemiEarn PoC: attacker flash-loans 51 WETH from Balancer, supplies 50 WETH into `aweth`, borrows 39.5 WETH against it, then calls `victim.liquidateBorrow{value: ...}(address(this), aweth /* collateral */, aweth /* borrowed */, amount)`. Because the vulnerable contract does not enforce `collateralAsset != borrowedAsset`, the liquidation runs with self as both liquidator and borrower AND with a de"
    WIKI_RECOMMENDATION = "Add `require(collateralAsset != borrowedAsset, \"same-asset liquidation\")` at the top of `liquidateBorrow`. Additionally assert `msg.sender != borrower` to block the self-liquidator-rebate variant, and clamp `repayAmount <= closeFactor * borrowBalance` so even a legitimate liquidator cannot fully u"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(borrow|debt|collateral|supplyBalance|accountBorrows)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidateBorrow|liquidate|_liquidate|liquidatePosition)$'}, {'function.has_param_name_matching': '(?i)(collateral|collateralAsset|collateralToken|assetCollateral)'}, {'function.body_contains_regex': {'regex': '(transfer|_transfer|safeTransfer|seize|seizeInternal)\\s*\\('}}, {'function.body_not_contains_regex': '(require|assert)\\s*\\(\\s*(collateral(Asset|Token)?|assetCollateral)\\s*!=\\s*(borrow(ed)?(Asset|Token)?|assetBorrowed)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — self-liquidation-same-collateral-borrow-asset: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
