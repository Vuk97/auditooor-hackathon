use soroban_sdk::{contract, contractimpl};
pub struct Checkpoints;
impl Checkpoints { pub fn get_at_block(&self, _b: u64) -> u128 { 0 } }
#[contract]
pub struct Votes;
#[contractimpl]
impl Votes {
    // BUG: get_at_block with no same-block disambiguation
    pub fn get_weight(c: Checkpoints, block: u64) -> u128 {
        c.get_at_block(block)
    }
}
