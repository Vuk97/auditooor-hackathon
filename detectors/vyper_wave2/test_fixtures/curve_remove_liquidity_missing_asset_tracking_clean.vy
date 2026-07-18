# fixture: negative — curve_remove_liquidity_missing_asset_tracking (CLEAN)
# Fix: register ALL received tokens unconditionally after remove_liquidity

# @version ^0.3.10

assets: DynArray[address, 10]
token_a: address
token_b: address
curve_pool: address

@external
def exit_pool(lp_amount: uint256, min_amounts: uint256[2]):
    remove_liquidity(self.curve_pool, lp_amount, min_amounts)
    # Fix: always register all tokens received, regardless of min_amounts
    received_tokens: address[2] = [self.token_a, self.token_b]
    for i in range(2):
        self.assets.append(received_tokens[i])
