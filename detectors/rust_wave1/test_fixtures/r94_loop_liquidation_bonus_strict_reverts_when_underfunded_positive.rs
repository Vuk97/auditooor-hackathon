use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Engine;
#[contractimpl]
impl Engine {
    // BUG: required strict-asserted <= collateral, no cap/clamp
    pub fn liquidate(debt: u128, bonus: u128, collateral: u128) -> u128 {
        let required = debt + debt * bonus / 100;
        require(required <= collateral);
        required
    }
}
fn require(_b: bool) {}
