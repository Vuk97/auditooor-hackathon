use soroban_sdk::{contract, contractimpl};
pub struct Pool;
impl Pool { pub fn get_rate(&self) -> u128 { 0 } }
#[contract]
pub struct LpOracle;
#[contractimpl]
impl LpOracle {
    // BUG: reads pool.get_rate() without reentrancy guard
    pub fn get_price(pool: Pool, underlying_price: u128) -> u128 {
        pool.get_rate() * underlying_price
    }
}
