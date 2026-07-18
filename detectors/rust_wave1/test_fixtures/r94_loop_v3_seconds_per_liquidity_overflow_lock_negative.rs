use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStaker;
#[contractimpl]
impl SafeStaker {
    // OK: uses wrapping_sub for intentional overflow wrap
    pub fn unstake(current: u128, initial: u128) -> u128 {
        let seconds_per_liquidity_inside = current;
        seconds_per_liquidity_inside.wrapping_sub(initial)
    }
}
