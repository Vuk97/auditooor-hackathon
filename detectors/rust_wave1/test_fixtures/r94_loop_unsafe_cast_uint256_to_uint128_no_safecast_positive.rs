use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Farm;
#[contractimpl]
impl Farm {
    // BUG: direct u256 → u128 cast without SafeCast
    pub fn update_reward(amount: u128) -> u128 {
        let big: u128 = amount * 10;
        let small = big as u128;
        let truncated = small as u128;
        let _ = truncated;
        let sol_cast = small as u128;
        let _ = sol_cast;
        // simulate downcast via 'as u128' on what would be u256 equivalent
        let result = (big as u128) as u128;
        result
    }

    pub fn apply_fees(reserve: u128) -> u128 {
        // explicit uint128(amount) style via Rust `as u128`
        reserve as u128
    }
}
