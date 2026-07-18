use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct YTReward;
#[contractimpl]
impl YTReward {
    // BUG: reward proportional to user_yt_balance / total_yt_supply (live)
    pub fn claim_external_reward(user: u64) -> u128 {
        let reward = pool_rewards() * user_yt_balance(user) / total_yt_supply();
        reward
    }
}
fn pool_rewards() -> u128 { 0 }
fn user_yt_balance(_u: u64) -> u128 { 0 }
fn total_yt_supply() -> u128 { 0 }
