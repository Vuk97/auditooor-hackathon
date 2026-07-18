use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Vault;
#[contractimpl]
impl Vault {
    // BUG: distributes pending_rewards pro-rata to current shares, no cooldown
    pub fn allocate(user: u64) -> u128 {
        let share_of = shares_of(user);
        let reward = pending_rewards() * share_of;
        reward
    }
}
fn pending_rewards() -> u128 { 0 }
fn shares_of(_u: u64) -> u128 { 0 }
