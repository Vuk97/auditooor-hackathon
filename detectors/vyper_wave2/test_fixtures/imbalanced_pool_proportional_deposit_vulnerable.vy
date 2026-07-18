# fixture: positive — imbalanced_pool_proportional_deposit (VULNERABLE)
# Bug: restore always calls add_liquidity proportionally, no imbalance check

# @version ^0.3.10

curve_pool: address
token_a: address
token_b: address

@external
def restore(amount_a: uint256, amount_b: uint256):
    # Bug: always does proportional add_liquidity without checking pool balance
    # When pool is imbalanced, this yields fewer LP tokens
    add_liquidity(self.curve_pool, [amount_a, amount_b], 0)
