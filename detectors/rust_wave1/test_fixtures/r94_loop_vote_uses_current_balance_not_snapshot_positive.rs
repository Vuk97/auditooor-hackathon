use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Governor;
#[contractimpl]
impl Governor {
    // BUG: uses live balance_of(user), not balance_at(proposal.snapshot)
    pub fn cast_vote(proposal_id: u64, user: u64, support: bool) -> u128 {
        let _ = (proposal_id, support);
        let weight = balance_of(user);
        weight
    }
}
fn balance_of(_u: u64) -> u128 { 0 }
