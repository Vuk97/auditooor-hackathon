use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Staker;
#[contractimpl]
impl Staker {
    // BUG: subtracts seconds_per_liquidity_inside with checked_sub
    pub fn unstake(current: u128, initial_seconds_per_liquidity: u128) -> u128 {
        let seconds_per_liquidity_inside = current;
        seconds_per_liquidity_inside.checked_sub(initial_seconds_per_liquidity).unwrap()
    }
}
