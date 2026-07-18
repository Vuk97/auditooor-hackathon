use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Timelock;
impl Timelock {
    // BUG: ctor grants DEFAULT_ADMIN_ROLE to deployer, no revoke anywhere
    pub fn new() -> Self {
        grant_role(DEFAULT_ADMIN_ROLE, msg_sender());
        Timelock
    }
}
#[contractimpl]
impl Timelock {
    pub fn noop() {}
}
fn grant_role(_r: u32, _a: u64) {}
fn msg_sender() -> u64 { 0 }
const DEFAULT_ADMIN_ROLE: u32 = 0;
