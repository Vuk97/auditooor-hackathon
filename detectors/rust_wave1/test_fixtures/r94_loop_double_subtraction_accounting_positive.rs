use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: cash_reserve subtracted TWICE
    pub fn deposit_limit_breached(total_assets: u128, cash_reserve: u128, limit: u128) -> bool {
        let used = total_assets - cash_reserve - cash_reserve;
        used > limit
    }
    // BUG (sequential): -= same var twice
    pub fn process(mut available: u128, reserved: u128) -> u128 {
        available -= reserved;
        available -= reserved;
        available
    }
}
