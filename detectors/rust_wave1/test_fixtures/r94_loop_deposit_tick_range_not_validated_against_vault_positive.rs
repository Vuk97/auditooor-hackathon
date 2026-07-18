use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: accepts tick_lower/tick_upper but doesn't check against vault's range
    pub fn deposit_fixed(tick_lower: i32, tick_upper: i32, amount: u128) -> u128 {
        let _ = (tick_lower, tick_upper);
        provide_liquidity(tick_lower, tick_upper, amount)
    }
}
fn provide_liquidity(_l: i32, _u: i32, _a: u128) -> u128 { 0 }
