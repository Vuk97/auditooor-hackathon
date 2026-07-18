use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeGovernor;
#[contractimpl]
impl SafeGovernor {
    // OK: reads balance_of_at the proposal's snapshot block
    pub fn cast_vote(proposal_id: u64, user: u64, support: bool, snapshot_block: u64) -> u128 {
        let _ = (proposal_id, support);
        let weight = balance_of_at(user, snapshot_block);
        weight
    }
}
fn balance_of_at(_u: u64, _b: u64) -> u128 { 0 }
