use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Boost;
#[contractimpl]
impl Boost {
    // BUG: sets lock_status without calling update_reward first
    pub fn set_lock_status(user: u64, locked: bool) {
        let _ = user;
        let mut lock_status = false;
        lock_status = locked;
        let _ = lock_status;
    }
}
