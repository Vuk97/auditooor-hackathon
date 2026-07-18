# fixture: positive — slippage_single_side_bypass (VULNERABLE)
# Bug: slippage computed for proportional path then passed to single-side exit

# @version ^0.3.10

curve_pool: address

@internal
def _getMinExitAmounts(lp_amount: uint256) -> uint256[2]:
    # Calculates minimum amounts for proportional withdrawal
    return [lp_amount / 2, lp_amount / 2]

@external
def redeem(lp_amount: uint256, single_side: bool):
    min_amounts: uint256[2] = self._getMinExitAmounts(lp_amount)
    if single_side:
        # Bug: uses proportional min_amounts for single-side exit
        # single-side slippage should be computed differently
        remove_liquidity_one_coin(self.curve_pool, lp_amount, 0, min_amounts[0])
    else:
        remove_liquidity(self.curve_pool, lp_amount, min_amounts)
