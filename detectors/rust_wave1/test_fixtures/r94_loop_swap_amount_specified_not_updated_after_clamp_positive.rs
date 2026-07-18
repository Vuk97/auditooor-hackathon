use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: clamps sqrt_price_next but doesn't reduce amount_specified
    pub fn swap(mut amount_specified: u128, sqrt_price_limit: u128) -> u128 {
        let mut sqrt_price_next = 1_000_000u128;
        if sqrt_price_next > sqrt_price_limit {
            sqrt_price_next = sqrt_price_limit;
        }
        let _ = amount_specified;
        sqrt_price_next
    }
}
