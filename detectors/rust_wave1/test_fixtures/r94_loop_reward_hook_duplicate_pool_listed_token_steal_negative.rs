use soroban_sdk::{contract, contractimpl};
use std::collections::HashMap;
type Address = [u8; 20];
pub struct Key { currency0: Address, currency1: Address, fee: u32, tick_spacing: i32, hook: Address }
fn send_reward(_who: Address, _amount: u64) {}
fn load_rewards_per_pair() -> HashMap<(Address, Address), u64> { HashMap::new() }
fn canonical_pool_for_pair(_a: Address, _b: Address) -> Key {
    Key { currency0: [0; 20], currency1: [0; 20], fee: 3000, tick_spacing: 60, hook: [0; 20] }
}
#[contract]
pub struct RewardHook;
#[contractimpl]
impl RewardHook {
    // SAFE: asserts fee / tick_spacing / hook match the canonical pool for the pair
    pub fn distribute_rewards(lp: Address, token0: Address, token1: Address, key: Key) {
        let canonical = canonical_pool_for_pair(token0, token1);
        assert!(key.fee == canonical.fee && key.tick_spacing == canonical.tick_spacing && key.hook == canonical.hook);
        let rewards_per_pair = load_rewards_per_pair();
        let amount = *rewards_per_pair.get(&(token0, token1)).unwrap_or(&0);
        send_reward(lp, amount);
    }
}
