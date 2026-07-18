use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeStaking;
#[contractimpl]
impl SafeStaking {
    // OK: asserts reward != underlying stake_token
    pub fn add_reward(reward_token: u64, rate: u128) {
        let stake_token = 0u64;
        if reward_token == stake_token { panic!("reward == underlying"); }
        reward_rate().set(reward_token, rate);
    }
}
fn reward_rate() -> Map { Map }
struct Map; impl Map { fn set(&self, _k: u64, _v: u128) {} }
