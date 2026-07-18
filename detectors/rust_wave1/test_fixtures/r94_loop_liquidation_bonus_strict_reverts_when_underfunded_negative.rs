use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEngine;
#[contractimpl]
impl SafeEngine {
    // OK: clamps the required amount to available collateral via min
    pub fn liquidate(debt: u128, bonus: u128, collateral: u128) -> u128 {
        let required = debt + debt * bonus / 100;
        let _sanity = required;
        let bonus_seize = std::cmp::min(required, collateral);
        bonus_seize
    }
}
