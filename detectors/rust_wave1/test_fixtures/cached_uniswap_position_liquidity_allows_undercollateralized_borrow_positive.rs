use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Position {
    token_id: u64,
}

#[derive(Clone, Debug)]
struct LiquidityInfo {
    liquidity: u128,
    cached_at_deposit: u64,
}

struct LendingVault {
    positions: HashMap<u64, Position>,
    // BUG: Cached liquidity stored at deposit time, never refreshed
    liquidity_cache: HashMap<u64, LiquidityInfo>,
}

impl LendingVault {
    fn new() -> Self {
        Self {
            positions: HashMap::new(),
            liquidity_cache: HashMap::new(),
        }
    }

    fn get_position_liquidity_at_deposit(&self, token_id: u64) -> u128 {
        // Return the cached value from deposit time
        self.liquidity_cache.get(&token_id).unwrap().liquidity
    }

    fn deposit_collateral(&mut self, token_id: u64) {
        let position = Position { token_id };
        // BUG: Cache liquidity at deposit time, never update it
        let liquidity_at_deposit = self.query_amm_liquidity(token_id);
        self.liquidity_cache.insert(token_id, LiquidityInfo {
            liquidity: liquidity_at_deposit,
            cached_at_deposit: 1, // block timestamp
        });
        self.positions.insert(token_id, position);
    }

    fn query_amm_liquidity(&self, token_id: u64) -> u128 {
        // Simulate AMM call
        1000u128
    }

    // BUG: Uses cached liquidity instead of current liquidity
    fn get_collateral_value(&self, token_id: u64) -> u128 {
        // Uses stale cached value - attacker can reduce liquidity after deposit
        let cached_liquidity = self.get_position_liquidity_at_deposit(token_id);
        cached_liquidity * 2 // price factor
    }

    fn borrow_against(&self, token_id: u64, amount: u128) -> bool {
        let collateral_value = self.get_collateral_value(token_id);
        collateral_value >= amount * 150 / 100 // 150% collateralization
    }
}

fn main() {
    let mut vault = LendingVault::new();
    vault.deposit_collateral(42);
    // Attacker removes liquidity from Uniswap position here
    // But vault still thinks full liquidity exists
    assert!(vault.borrow_against(42, 1000)); // Undercollateralized borrow!
}