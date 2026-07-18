use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: reduces amount_specified after price clamp
    pub fn swap(mut amount_specified: u128, sqrt_price_limit: u128) -> u128 {
        let mut sqrt_price_next = 1_000_000u128;
        if sqrt_price_next > sqrt_price_limit {
            sqrt_price_next = sqrt_price_limit;
            let consumed = 500u128;
            amount_specified -= consumed;
        }
        let _ = amount_specified;
        sqrt_price_next
    }
}
