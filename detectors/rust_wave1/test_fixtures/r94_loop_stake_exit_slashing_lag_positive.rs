use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Relay;
#[contractimpl]
impl Relay {
    // BUG: sets sig verifier, module also has unstake() with no atomic guard
    pub fn set_sig_verifier(verifier: u64) {
        persist_verifier(verifier);
    }
    pub fn unstake(amount: u128) {
        release_stake(amount);
    }
}
fn persist_verifier(_v: u64) {}
fn release_stake(_a: u128) {}
