use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFeeManager;
#[contractimpl]
impl SafeFeeManager {
    // OK: require_healthy before decrementing user_debt
    pub fn offset_debt(user: u64, fee_pool: u128) -> u128 {
        require_healthy(user);
        let _ = user;
        let mut user_debt = 1000u128;
        user_debt -= fee_pool;
        user_debt
    }
}
fn require_healthy(_u: u64) {}
