use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStaking;
#[contractimpl]
impl SafeStaking {
    // OK: calls update_reward before reading stored index
    pub fn claim(user: u64) -> u128 {
        update_reward(user);
        let stored = reward_per_token_stored();
        let user_paid = reward_per_token_paid(user);
        let balance = balance_of(user);
        balance * (stored - user_paid) / 1_000_000_000
    }
}
fn update_reward(_u: u64) {}
fn reward_per_token_stored() -> u128 { 100 }
fn reward_per_token_paid(_u: u64) -> u128 { 50 }
fn balance_of(_u: u64) -> u128 { 1 }
