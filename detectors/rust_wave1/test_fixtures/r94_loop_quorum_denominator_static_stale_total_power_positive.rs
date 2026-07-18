use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Gov;
#[contractimpl]
impl Gov {
    // BUG: divides votes_for by cached total_power_in_tokens
    pub fn quorum_reached(votes_for: u128, quorum_bps: u128) -> bool {
        votes_for * 10_000 / total_power_in_tokens() >= quorum_bps
    }
}
fn total_power_in_tokens() -> u128 { 1_000_000 }
