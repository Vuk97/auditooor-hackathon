use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: ecrecover used without null-address check
    pub fn verify_sig(hash: u128, sig: u128) -> u64 {
        let signer = ecrecover(hash, sig);
        signer
    }
}
fn ecrecover(_h: u128, _s: u128) -> u64 { 0 }
