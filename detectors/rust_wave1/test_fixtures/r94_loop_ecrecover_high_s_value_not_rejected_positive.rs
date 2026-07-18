use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Sig;
#[contractimpl]
impl Sig {
    // BUG: ecrecover used without high-s bound check
    pub fn verify_sig(hash: u128, v: u8, r: u128, s: u128) -> u64 {
        let _ = (v, r, s);
        ecrecover(hash, v, r, s)
    }
}
fn ecrecover(_h: u128, _v: u8, _r: u128, _s: u128) -> u64 { 0 }
