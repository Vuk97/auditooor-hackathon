use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeRelay;
#[contractimpl]
impl SafeRelay {
    pub fn set_sig_verifier(verifier: u64) {
        persist_verifier(verifier);
    }
    pub fn unstake(amount: u128) {
        require(!in_atomic_set_change());
        release_stake(amount);
    }
}
fn persist_verifier(_v: u64) {}
fn release_stake(_a: u128) {}
fn in_atomic_set_change() -> bool { false }
fn require(_: bool) {}
