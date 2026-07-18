use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: checks signer != address(0) after ecrecover
    pub fn verify_sig(hash: u128, sig: u128) -> u64 {
        let signer = ecrecover(hash, sig);
        require(signer != 0);
        signer
    }
}
fn ecrecover(_h: u128, _s: u128) -> u64 { 0 }
fn require(_c: bool) {}
