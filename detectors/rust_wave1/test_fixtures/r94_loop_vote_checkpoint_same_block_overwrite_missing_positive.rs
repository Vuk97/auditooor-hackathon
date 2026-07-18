use soroban_sdk::{contract, contractimpl};
pub struct Checkpoint { from_block: u64, votes: u128 }
fn current_block() -> u64 { 100 }
fn load_checkpoints() -> Vec<Checkpoint> { Vec::new() }
fn save_checkpoints(_c: &Vec<Checkpoint>) {}
#[contract]
pub struct Votes;
#[contractimpl]
impl Votes {
    // BUG: always pushes a new checkpoint even if last has same block
    pub fn _write_checkpoint(new_votes: u128) {
        let mut checkpoints = load_checkpoints();
        checkpoints.push(Checkpoint { from_block: current_block(), votes: new_votes });
        save_checkpoints(&checkpoints);
    }
}
