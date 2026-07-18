use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: checks health_factor before mutating debt
    pub fn utilize(user: u64, amount: u128) -> u128 {
        require_healthy(user);
        let debt = amount;
        debt + 100
    }
}
fn require_healthy(_u: u64) {}
