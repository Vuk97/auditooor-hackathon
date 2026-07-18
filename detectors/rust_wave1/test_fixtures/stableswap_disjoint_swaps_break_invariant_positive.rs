use soroban_sdk::{contract, contractimpl};
fn stable_swap_step(_a: u128, _i: usize, _j: usize) -> u128 { 0 }
#[contract]
pub struct StablePool;
#[contractimpl]
impl StablePool {
    pub fn multihop_swap(amount_in: u128) -> u128 {
        let mid = stable_swap_step(amount_in, 0, 1);
        let out = stable_swap_step(mid, 1, 2);
        out
    }
}
