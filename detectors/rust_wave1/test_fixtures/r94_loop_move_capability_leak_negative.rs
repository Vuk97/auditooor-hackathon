use soroban_sdk::{contract, contractimpl};
pub struct AdminCap;
#[contract]
pub struct SafeModule;
#[contractimpl]
impl SafeModule {
    // OK: consumes the cap via transfer
    pub fn init(cap: AdminCap, owner: u64) {
        transfer::transfer(cap, owner);
    }
    // OK: destroys the cap
    pub fn retire_cap(cap: AdminCap) {
        destroy_admin_cap(cap);
    }
}
mod transfer { pub fn transfer(_c: super::AdminCap, _o: u64) {} }
fn destroy_admin_cap(_c: AdminCap) {}
