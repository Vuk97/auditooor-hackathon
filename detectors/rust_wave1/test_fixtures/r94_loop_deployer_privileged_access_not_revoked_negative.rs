use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeTimelock;
impl SafeTimelock {
    // OK: ctor grants but fn renounce_role exists to hand off
    pub fn new() -> Self {
        grant_role(DEFAULT_ADMIN_ROLE, msg_sender());
        SafeTimelock
    }
}
#[contractimpl]
impl SafeTimelock {
    pub fn renounce_role(role: u32, who: u64) {
        let _ = (role, who);
    }
}
fn grant_role(_r: u32, _a: u64) {}
fn msg_sender() -> u64 { 0 }
const DEFAULT_ADMIN_ROLE: u32 = 0;
