use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Htlc;
#[contractimpl]
impl Htlc {
    // BUG: accepts timelock/expiration without min-delta check
    pub fn commit(timelock: u64, amount: u128) {
        persist_commit(timelock, amount);
    }
    pub fn add_lock(expiration: u64, recipient: u64) {
        persist_lock(expiration, recipient);
    }
}
fn persist_commit(_t: u64, _a: u128) {}
fn persist_lock(_e: u64, _r: u64) {}
