use soroban_sdk::{contract, contractimpl};
// UUPSUpgradeable marker present
trait UUPSUpgradeable { fn authorize_upgrade(&self, new_impl: u64); }
#[contract]
pub struct Impl;
#[contractimpl]
impl Impl {
    // BUG: has initialize() but no _disable_initializers() call
    pub fn initialize(owner: u64) {
        let _ = owner;
    }
    fn authorize_upgrade(_new_impl: u64) {}
}
