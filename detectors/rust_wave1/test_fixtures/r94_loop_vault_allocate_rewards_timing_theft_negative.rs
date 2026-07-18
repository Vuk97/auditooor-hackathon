use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVault;
#[contractimpl]
impl SafeVault {
    // OK: uses snapshot_shares taken at allocate-start, not current
    pub fn allocate(user: u64) -> u128 {
        let snapshot_shares = last_allocate_shares(user);
        let share_of = shares_of(user);
        let _ = share_of;
        let reward = pending_rewards() * snapshot_shares;
        reward
    }
}
fn pending_rewards() -> u128 { 0 }
fn shares_of(_u: u64) -> u128 { 0 }
fn last_allocate_shares(_u: u64) -> u128 { 0 }
