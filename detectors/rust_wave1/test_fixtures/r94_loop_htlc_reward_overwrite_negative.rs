use soroban_sdk::{contract, contractimpl};
pub struct Lock { pub reward: u128 }
#[contract]
pub struct SafeHtlc;
#[contractimpl]
impl SafeHtlc {
    // OK: requires previous reward is zero (or unset)
    pub fn lock_reward(lock: &mut Lock, amount: u128) {
        require(lock.reward == 0);
        lock.reward = amount;
    }
    // OK: preserves previous via add
    pub fn add_reward(lock: &mut Lock, amount: u128) {
        let previous_reward = lock.reward;
        lock.reward = previous_reward + amount;
    }
}
fn require(_: bool) {}
