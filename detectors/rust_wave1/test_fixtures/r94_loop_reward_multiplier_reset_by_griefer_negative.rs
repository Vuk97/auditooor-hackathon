use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeDistributor;
#[contractimpl]
impl SafeDistributor {
    // OK: require_auth(user) before mutating user's multiplier
    pub fn handle_balance_update(user: u64, delta: u128) {
        require_auth(user);
        let _ = delta;
        let mut multiplier = 0u128;
        multiplier = 1;
        let _ = multiplier;
    }
}
fn require_auth(_u: u64) {}
