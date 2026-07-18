use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFarm;
#[contractimpl]
impl SafeFarm {
    // OK: uses u128::try_from instead of bare `as u128`
    pub fn update_reward(amount: u128) -> u128 {
        let big: u128 = amount * 10;
        let small = u128::try_from(big).unwrap();
        small
    }
}
