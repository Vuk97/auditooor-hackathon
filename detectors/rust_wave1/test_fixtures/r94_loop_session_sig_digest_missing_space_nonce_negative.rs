use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSession;
#[contractimpl]
impl SafeSession {
    // OK: digest includes space, nonce, and chain_id
    pub fn session_digest(calls: u128, session_id: u64, space: u64, nonce: u64, chain_id: u64) -> u128 {
        keccak256(&(calls, session_id, space, nonce, chain_id))
    }
}
fn keccak256(_k: &(u128, u64, u64, u64, u64)) -> u128 { 0 }
