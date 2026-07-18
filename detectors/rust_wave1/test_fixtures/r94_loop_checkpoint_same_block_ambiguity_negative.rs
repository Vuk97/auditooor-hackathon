use soroban_sdk::{contract, contractimpl};
pub struct Checkpoints;
impl Checkpoints { pub fn get_at_block(&self, _b: u64) -> u128 { 0 } }
#[contract]
pub struct SafeVotes;
#[contractimpl]
impl SafeVotes {
    // OK: disambiguates via timestamp
    pub fn get_weight(c: Checkpoints, block: u64, timestamp: u64) -> u128 {
        let base = c.get_at_block(block);
        base + (timestamp as u128)
    }
}
