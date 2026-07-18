use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn balance_of(_token: Address, _who: Address) -> u64 { 100_000 }
fn accRewardPerShare() -> u64 { 1_000 }
fn is_pool_or_vault(_addr: Address) -> bool { false }
#[contract]
pub struct IncentivizedERC20;
#[contractimpl]
impl IncentivizedERC20 {
    // SAFE: excludes wrapper-pool / vault addresses from reward accrual
    pub fn pending_reward(token: Address, user: Address) -> u64 {
        if is_pool_or_vault(user) {
            return 0;
        }
        let bal = balance_of(token, user);
        let acc_reward_per_share = accRewardPerShare();
        bal * acc_reward_per_share
    }
}
