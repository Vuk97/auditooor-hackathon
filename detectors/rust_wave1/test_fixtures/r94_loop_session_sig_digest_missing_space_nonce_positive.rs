use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Session;
#[contractimpl]
impl Session {
    // BUG: digest omits space/nonce/chain_id
    pub fn session_digest(calls: u128, session_id: u64) -> u128 {
        keccak256(&(calls, session_id))
    }
}
fn keccak256(_k: &(u128, u64)) -> u128 { 0 }
