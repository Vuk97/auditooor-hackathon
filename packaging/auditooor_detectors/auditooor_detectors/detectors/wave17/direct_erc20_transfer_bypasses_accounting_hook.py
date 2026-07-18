"""
direct-erc20-transfer-bypasses-accounting-hook — generated from reference/patterns.dsl/direct-erc20-transfer-bypasses-accounting-hook.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py direct-erc20-transfer-bypasses-accounting-hook.yaml
Source: auditooor-R75-nethermind-uspd-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DirectErc20TransferBypassesAccountingHook(AbstractDetector):
    ARGUMENT = "direct-erc20-transfer-bypasses-accounting-hook"
    HELP = "Per-position escrows that measure their collateral via IERC20(asset).balanceOf(address(this)) AND rely on deposit-reporting hooks to update a separate global accounting value allow the owner to 'launder' collateral by transferring tokens directly to the escrow — the balanceOf grows (making the posit"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/direct-erc20-transfer-bypasses-accounting-hook.yaml"
    WIKI_TITLE = "Escrow tracks collateral via balanceOf while relying on hooks — direct transfer bypasses global accounting"
    WIKI_DESCRIPTION = "Two-layer accounting is dangerous when one layer (per-position) is read directly from ERC20 balanceOf while the other layer (global collateralization ratio, insolvency snapshot) is only updated via explicit add/remove functions. A malicious stabilizer/position-owner can (1) perform a raw ERC20.transfer into their escrow to bump the per-position ratio, (2) call removeExcessCollateral which DOES cal"
    WIKI_EXPLOIT_SCENARIO = "Two positions are collateralized at 90% (insolvent). Position-owner Alice transfers stETH directly to her PositionEscrow via ERC20.transfer(escrow, X). Her positionRatio is now 110%, but the global reporter.systemRatio is still 90%. Liquidator tries to liquidate Alice: liquidatePosition reverts because positionRatio (110%) > systemRatio (90%) triggers LiquidationNotBelowSystemRatio. Alice then cal"
    WIKI_RECOMMENDATION = "Track collateral via an internal variable that is incremented only inside addCollateral* functions; do NOT use balanceOf for per-position measurement when a global accounting layer exists. Sweep/skim any unsolicited direct transfers (or leave them stuck) rather than crediting them to positionRatio."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Escrow|Vault|Position|Silo).*(balanceOf|IERC20)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(addCollateral|deposit|supply|depositStEth|addStETH|addLiquidity)'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(transferFrom|safeTransferFrom)\\s*\\('}, {'function.body_contains_regex': 'reportCollateralAddition|notifyDeposit|updateSnapshot|reportAddition'}, {'function.body_not_contains_regex': '(_trackedBalance|internalBalance|accountedBalance|_balances\\[)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — direct-erc20-transfer-bypasses-accounting-hook: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
