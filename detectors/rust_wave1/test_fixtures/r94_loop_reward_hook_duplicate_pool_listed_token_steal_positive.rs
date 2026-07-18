use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
fn send_reward(_who: Address, _amount: u64) {}
fn load_rewards_per_pair() -> HashMap<(Address, Address), u64> { HashMap::new() }
#[contract]
pub struct RewardHook;
#[contractimpl]
impl RewardHook {
    // BUG: rewards keyed on (token0, token1) pair only — no fee / tick / hook check
    pub fn distribute_rewards(lp: Address, token0: Address, token1: Address) {
        let rewards_per_pair = load_rewards_per_pair();
        let amount = *rewards_per_pair.get(&(token0, token1)).unwrap_or(&0);
        send_reward(lp, amount);
    }
}
