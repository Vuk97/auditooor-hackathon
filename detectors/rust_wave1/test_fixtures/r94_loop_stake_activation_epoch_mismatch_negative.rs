use soroban_sdk::{contract, contractimpl};
pub struct StakedWal { pub node_id: u64, pub activation_epoch: u64, pub withdraw_epoch: u64 }
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: also enforces activation_epoch equality
    pub fn join(a: StakedWal, b: StakedWal) {
        require(a.node_id == b.node_id);
        require(a.activation_epoch == b.activation_epoch);
        require(a.withdraw_epoch == b.withdraw_epoch);
    }
}
fn require(_: bool) {}
