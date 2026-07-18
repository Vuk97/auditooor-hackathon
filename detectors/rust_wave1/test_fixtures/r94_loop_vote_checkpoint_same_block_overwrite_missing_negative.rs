use soroban_sdk::{contract, contractimpl};
pub struct Checkpoint { from_block: u64, votes: u128 }
fn current_block() -> u64 { 100 }
fn load_checkpoints() -> Vec<Checkpoint> { Vec::new() }
fn save_checkpoints(_c: &Vec<Checkpoint>) {}
#[contract]
pub struct Votes;
#[contractimpl]
impl Votes {
    // SAFE: if last checkpoint is from the current block, overwrite instead of appending
    pub fn _write_checkpoint(new_votes: u128) {
        let mut checkpoints = load_checkpoints();
        let pos = checkpoints.len();
        if pos > 0 && checkpoints[pos - 1].from_block == current_block() {
            checkpoints[pos - 1].votes = new_votes;
        } else {
            checkpoints.push(Checkpoint { from_block: current_block(), votes: new_votes });
        }
        save_checkpoints(&checkpoints);
    }
}
