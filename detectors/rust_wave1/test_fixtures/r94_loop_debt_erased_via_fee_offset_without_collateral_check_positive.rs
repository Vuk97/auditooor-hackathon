use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct FeeManager;
#[contractimpl]
impl FeeManager {
    // BUG: decrements user_debt without health check
    pub fn offset_debt(user: u64, fee_pool: u128) -> u128 {
        let _ = user;
        let mut user_debt = 1000u128;
        user_debt -= fee_pool;
        user_debt
    }
}
