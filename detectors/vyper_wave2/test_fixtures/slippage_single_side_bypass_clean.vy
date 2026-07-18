# fixture: negative — slippage_single_side_bypass (CLEAN)
# Fix: compute separate single-side min for single-asset exit path

# @version ^0.3.10

curve_pool: address

@internal
def _getMinExitAmounts(lp_amount: uint256) -> uint256[2]:
    return [lp_amount / 2, lp_amount / 2]

@internal
def _get_single_min(lp_amount: uint256, token_idx: uint256) -> uint256:
    # single_min: separate calculation for single-side exit
    return ICurvePool(self.curve_pool).calc_withdraw_one_coin(lp_amount, convert(token_idx, int128)) * 99 / 100

@external
def redeem(lp_amount: uint256, single_side: bool):
    if single_side:
        # Fix: compute single-asset minimum separately
        single_min: uint256 = self._get_single_min(lp_amount, 0)
        remove_liquidity_one_coin(self.curve_pool, lp_amount, 0, single_min)
    else:
        min_amounts: uint256[2] = self._getMinExitAmounts(lp_amount)
        remove_liquidity(self.curve_pool, lp_amount, min_amounts)
