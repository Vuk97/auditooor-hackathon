use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeGov;
#[contractimpl]
impl SafeGov {
    // OK: uses live total_voting_power()
    pub fn quorum_reached(votes_for: u128, quorum_bps: u128) -> bool {
        votes_for * 10_000 / total_voting_power() >= quorum_bps
    }
}
fn total_voting_power() -> u128 { 900_000 }
