use soroban_sdk::{contract, contractimpl};
pub struct Lock { pub reward: u128 }
#[contract]
pub struct Htlc;
#[contractimpl]
impl Htlc {
    // BUG: writes lock.reward with no preservation check
    pub fn lock_reward(lock: &mut Lock, amount: u128) {
        lock.reward = amount;
    }
    pub fn set_reward(lock: &mut Lock, amount: u128) {
        lock.reward = amount;
    }
}
