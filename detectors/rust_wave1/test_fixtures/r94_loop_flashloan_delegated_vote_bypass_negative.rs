use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeGovernor;
#[contractimpl]
impl SafeGovernor {
    pub fn vote_by_delegate(delegator: u64, snapshot_block: u64) -> bool {
        let weight = get_past_votes(delegator, snapshot_block);
        weight > 0
    }
}
fn get_past_votes(_d: u64, _b: u64) -> u128 { 0 }
