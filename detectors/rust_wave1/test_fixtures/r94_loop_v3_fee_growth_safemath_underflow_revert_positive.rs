use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Position;
#[contractimpl]
impl Position {
    // BUG: fee_growth subtraction uses checked_sub, panics on intentional underflow
    pub fn fee_growth(fee_growth_global: u128, fee_growth_below: u128, fee_growth_above: u128) -> u128 {
        fee_growth_global.checked_sub(fee_growth_below).unwrap()
            .checked_sub(fee_growth_above).unwrap()
    }
}
