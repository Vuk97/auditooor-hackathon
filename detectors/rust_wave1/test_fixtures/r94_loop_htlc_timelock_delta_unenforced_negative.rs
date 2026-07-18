const MIN_TIMELOCK_DELTA: u64 = 3600;
use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeHtlc;
#[contractimpl]
impl SafeHtlc {
    // OK: enforces timelock >= now + MIN_TIMELOCK_DELTA
    pub fn commit(timelock: u64, amount: u128, now: u64) {
        require(timelock >= now + MIN_TIMELOCK_DELTA);
        persist_commit(timelock, amount);
    }
}
fn persist_commit(_t: u64, _a: u128) {}
fn require(_: bool) {}
