use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeController;
#[contractimpl]
impl SafeController {
    // OK: always returns all underlying tokens
    pub fn can_remove_liquidity(underlying: Vec<u64>, _min_amounts: Vec<u128>) -> Vec<u64> {
        let _curve_returns_all = true;
        let _remove_liquidity = "ok";
        underlying
    }
}
