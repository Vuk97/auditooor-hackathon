# fixture: negative — imbalanced_pool_proportional_deposit (CLEAN)
# Fix: check pool balance ratio and use single-side deposit when imbalanced

# @version ^0.3.10

curve_pool: address
token_a: address
token_b: address

@internal
def is_imbalanced(pool: address) -> bool:
    balances: uint256[2] = ICurvePool(pool).get_balances()
    ratio: uint256 = balances[0] * 10**18 / balances[1]
    return ratio > 12 * 10**17 or ratio < 8 * 10**17  # >20% imbalance

@external
def restore(amount_a: uint256, amount_b: uint256):
    # Fix: check imbalance before choosing deposit path
    if self.is_imbalanced(self.curve_pool):
        # single-side deposit when imbalanced
        add_liquidity_one_coin(self.curve_pool, amount_a, 0, 0)
    else:
        add_liquidity(self.curve_pool, [amount_a, amount_b], 0)
