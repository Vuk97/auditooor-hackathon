use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePosition;
#[contractimpl]
impl SafePosition {
    // OK: uses wrapping_sub (intentional underflow wrapping)
    pub fn fee_growth(fee_growth_global: u128, fee_growth_below: u128, fee_growth_above: u128) -> u128 {
        let a = fee_growth_global.wrapping_sub(fee_growth_below);
        a.wrapping_sub(fee_growth_above)
    }
}
