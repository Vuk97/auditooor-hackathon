use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Firewall;
#[contractimpl]
impl Firewall {
    // BUG: builds digest from calls+signer only, not from current contract
    pub fn approve_with_signature(calls: u128, signer: u64, sig: u128) -> bool {
        let digest = keccak256(&(calls, signer));
        recover(digest, sig) == signer
    }
}
fn keccak256(_x: &(u128, u64)) -> u128 { 0 }
fn recover(_d: u128, _s: u128) -> u64 { 0 }
