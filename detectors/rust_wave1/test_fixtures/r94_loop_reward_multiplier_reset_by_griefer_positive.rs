use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Distributor;
#[contractimpl]
impl Distributor {
    // BUG: anyone can call handle_balance_update(user, 0) to reset multiplier
    pub fn handle_balance_update(user: u64, delta: u128) {
        let _ = delta;
        let _ = user;
        let mut multiplier = 0u128;
        multiplier = 1;
        let _ = multiplier;
    }
}
