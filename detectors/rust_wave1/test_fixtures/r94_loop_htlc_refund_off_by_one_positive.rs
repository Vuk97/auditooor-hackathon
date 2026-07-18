use soroban_sdk::{contract, contractimpl};
pub struct Lock { pub timelock: u64 }
#[contract]
pub struct Htlc;
#[contractimpl]
impl Htlc {
    // BUG: strict < between now and timelock
    pub fn refund(now: u64, lock: &Lock) {
        require(now < lock.timelock);
        release_funds();
    }
}
fn require(_: bool) {}
fn release_funds() {}
