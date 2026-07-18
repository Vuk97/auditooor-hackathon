use soroban_sdk::{contract, contractimpl};
pub struct StakedWal { pub node_id: u64, pub activation_epoch: u64, pub withdraw_epoch: u64 }
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: checks node_id + withdraw_epoch but not activation_epoch
    pub fn join(a: StakedWal, b: StakedWal) {
        require(a.node_id == b.node_id);
        require(a.withdraw_epoch == b.withdraw_epoch);
    }
}
fn require(_: bool) {}
