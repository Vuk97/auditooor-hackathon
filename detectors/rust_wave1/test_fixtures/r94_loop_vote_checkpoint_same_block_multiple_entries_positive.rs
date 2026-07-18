use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Votes;
#[contractimpl]
impl Votes {
    // BUG: pushes a new checkpoint each call with no same-block merge
    pub fn write_checkpoint(user: u64, new_power: u128) {
        let cp = Checkpoint { ts: now(), power: new_power };
        checkpoints(user).push(cp);
    }
}
struct Checkpoint { ts: u64, power: u128 }
fn now() -> u64 { 0 }
fn checkpoints(_u: u64) -> CpVec { CpVec }
struct CpVec;
impl CpVec { fn push(&self, _c: Checkpoint) {} }
