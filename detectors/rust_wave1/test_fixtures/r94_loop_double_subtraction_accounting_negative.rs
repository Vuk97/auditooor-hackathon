use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: single subtraction
    pub fn deposit_limit_breached(total_assets: u128, cash_reserve: u128, limit: u128) -> bool {
        let used = total_assets - cash_reserve;
        used > limit
    }
    // OK: sequential with different vars
    pub fn process(mut available: u128, reserved: u128, locked: u128) -> u128 {
        available -= reserved;
        available -= locked;
        available
    }
}
