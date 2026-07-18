use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBoost;
#[contractimpl]
impl SafeBoost {
    // OK: update_reward is called before mutating lock_status
    pub fn set_lock_status(user: u64, locked: bool) {
        update_reward(user);
        let mut lock_status = false;
        lock_status = locked;
        let _ = lock_status;
    }
}
fn update_reward(_u: u64) {}
