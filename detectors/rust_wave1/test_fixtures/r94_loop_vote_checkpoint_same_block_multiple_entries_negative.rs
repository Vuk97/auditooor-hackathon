use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeVotes;
#[contractimpl]
impl SafeVotes {
    // OK: mutates last entry when timestamp matches current block
    pub fn write_checkpoint(user: u64, new_power: u128) {
        let cps = checkpoints(user);
        if !cps.is_empty() && cps.last().ts == now() {
            cps.last_mut().power = new_power;
            return;
        }
        let cp = Checkpoint { ts: now(), power: new_power };
        cps.push(cp);
    }
}
struct Checkpoint { ts: u64, power: u128 }
fn now() -> u64 { 0 }
fn checkpoints(_u: u64) -> CpVec { CpVec }
struct CpVec;
impl CpVec {
    fn push(&self, _c: Checkpoint) {}
    fn is_empty(&self) -> bool { true }
    fn last(&self) -> Checkpoint { Checkpoint { ts: 0, power: 0 } }
    fn last_mut(&self) -> &mut Checkpoint { panic!() }
}
