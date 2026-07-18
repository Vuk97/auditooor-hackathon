use soroban_sdk::{contract, contractimpl};
pub struct Pool;
impl Pool { pub fn get_rate(&self) -> u128 { 0 } }
#[contract]
pub struct SafeLpOracle;
#[contractimpl]
impl SafeLpOracle {
    // OK: wraps with readonly-reentrancy check
    pub fn get_price(pool: Pool, underlying_price: u128) -> u128 {
        readonly_reentrancy_check();
        pool.get_rate() * underlying_price
    }
}
fn readonly_reentrancy_check() {}
