use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // BUG: accepts delegated vote without snapshotting
    pub fn vote_by_delegate(delegator: u64, support: bool, weight: u128) -> bool {
        let _ = (delegator, support, weight);
        true
    }
}
