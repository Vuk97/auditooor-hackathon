use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: utilize() mutates debt without health-factor check
    pub fn utilize(user: u64, amount: u128) -> u128 {
        let _ = user;
        let debt = amount;
        debt + 100
    }
}
