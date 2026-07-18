use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeHtlc;
#[contractimpl]
impl SafeHtlc {
    // OK: require hashlock != zero
    pub fn add_lock(hashlock: [u8; 32], amount: u128) {
        require(hashlock != [0; 32]);
        persist_lock(hashlock, amount);
    }
}
fn persist_lock(_h: [u8; 32], _a: u128) {}
fn require(_: bool) {}
