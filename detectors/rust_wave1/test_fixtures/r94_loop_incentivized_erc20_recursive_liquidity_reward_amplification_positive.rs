use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn balance_of(_token: Address, _who: Address) -> u64 { 100_000 }
fn accRewardPerShare() -> u64 { 1_000 }
#[contract]
pub struct IncentivizedERC20;
#[contractimpl]
impl IncentivizedERC20 {
    // BUG: rewards = balance_of * acc_reward_per_share, no wrapper-pool exclusion
    pub fn pending_reward(token: Address, user: Address) -> u64 {
        let bal = balance_of(token, user);
        let acc_reward_per_share = accRewardPerShare();
        bal * acc_reward_per_share
    }
}
