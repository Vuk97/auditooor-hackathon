use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Htlc;
#[contractimpl]
impl Htlc {
    // BUG: hashlock param persisted without zero-check
    pub fn add_lock(hashlock: [u8; 32], amount: u128) {
        persist_lock(hashlock, amount);
    }
    pub fn commit(hashlock: [u8; 32], recipient: u64) {
        persist_commit(hashlock, recipient);
    }
}
fn persist_lock(_h: [u8; 32], _a: u128) {}
fn persist_commit(_h: [u8; 32], _r: u64) {}
