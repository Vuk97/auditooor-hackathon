"""
lst-adapter-user-balance-not-cleared-after-redemption-fund-theft — generated from reference/patterns.dsl/lst-adapter-user-balance-not-cleared-after-redemption-fund-theft.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lst-adapter-user-balance-not-cleared-after-redemption-fund-theft.yaml
Source: auditooor-R76-cyfrin-sablier-bob-escrow-C1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LstAdapterUserBalanceNotClearedAfterRedemptionFundTheft(AbstractDetector):
    ARGUMENT = "lst-adapter-user-balance-not-cleared-after-redemption-fund-theft"
    HELP = "LST vault adapter redeem burns shares and pays WETH but never clears `_userWstETH[vault][user]`. Stale balance + ERC20 transfer of shares from another user inflates tracker on second redemption — drains other depositors."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lst-adapter-user-balance-not-cleared-after-redemption-fund-theft.yaml"
    WIKI_TITLE = "Yield-bearing adapter vault: `_userWstETH` not cleared on redeem → stale-balance double-pay"
    WIKI_DESCRIPTION = "An LST/yield-vault adapter tracks per-user staked-token balances in `_userWstETH[vaultId][user]`. The ERC-20 share-token's transfer hook (`onShareTransfer`) rebalances this mapping on non-zero-to-non-zero transfers, but burns (where `to == address(0)`) don't trigger the hook by design. The redemption path burns shares and computes payout via `calculateAmountToTransferWithYield` — a VIEW helper tha"
    WIKI_EXPLOIT_SCENARIO = "Three users each deposit 100 WETH. vault total wstETH = 300. Attacker controls 2 of the 3 deposits (A, B). Vault settles: unstake yields 330 WETH (yield). Attacker redeems A: shares burned, _userWstETH[A] still = 100, receives 100*330/300 = 110 WETH. Attacker transfers all B shares to A: onShareTransfer fires, _userWstETH[A] becomes 100 (stale) + 100 (transferred) = 200. Attacker redeems A again: "
    WIKI_RECOMMENDATION = "Make the payout calculation a STATE-CHANGING function that clears `_userWstETH[vaultId][user]` and decrements `_vaultTotalWstETH[vaultId]` before returning. The burn-then-compute ordering must treat per-user state like accounting: burn shares, THEN clear user wstETH, THEN transfer. Alternatively, ha"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)Adapter|Vault|LidoAdapter|StakingAdapter|YieldAdapter|Wrapper'}, {'contract.has_state_var_matching': '(?i)_userWstETH|_userStaked|_userBalance|_userYieldToken'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)redeem|withdraw|claimShare|processRedemption'}, {'function.body_contains_regex': '(?i)_burn\\(|share(Token)?\\.burn\\(|_update\\(|burnShares'}, {'function.body_contains_regex': '(?i)calculateAmountToTransfer|previewRedeem|_quoteRedeem|calculateWithYield'}, {'function.body_not_contains_regex': '(?i)_userWstETH\\[.*\\]\\[.*\\]\\s*=\\s*0|_userStaked\\[.*\\]\\[.*\\]\\s*=\\s*0|delete\\s+_userWstETH|clearUserWstETH|processRedemption\\(.*\\).*state.*changing'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lst-adapter-user-balance-not-cleared-after-redemption-fund-theft: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
