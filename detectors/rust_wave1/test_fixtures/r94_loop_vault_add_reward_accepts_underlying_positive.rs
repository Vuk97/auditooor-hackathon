use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Staking;
#[contractimpl]
impl Staking {
    // BUG: no check that reward_token != stake_token
    pub fn add_reward(reward_token: u64, rate: u128) {
        reward_rate().set(reward_token, rate);
        reward_tokens().push(reward_token);
    }
}
fn reward_rate() -> Map { Map }
fn reward_tokens() -> Vec { Vec }
struct Map; impl Map { fn set(&self, _k: u64, _v: u128) {} }
struct Vec; impl Vec { fn push(&self, _k: u64) {} }
