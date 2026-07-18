# fixture: positive — curve_remove_liquidity_missing_asset_tracking (VULNERABLE)
# Bug: only registers tokens in assets list when min_amounts[i] > 0

# @version ^0.3.10

assets: DynArray[address, 10]
token_a: address
token_b: address
curve_pool: address

@external
def exit_pool(lp_amount: uint256, min_amounts: uint256[2]):
    # Call remove_liquidity on the Curve pool
    remove_liquidity(self.curve_pool, lp_amount, min_amounts)
    # Bug: only tracking tokens where min_amount > 0
    # Tokens with min_amounts[i] == 0 are silently dropped from assets list
    if min_amounts[0] > 0:
        self.assets.append(self.token_a)
    if min_amounts[1] > 0:
        self.assets.append(self.token_b)
