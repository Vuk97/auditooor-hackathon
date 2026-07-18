use soroban_sdk::{contract, contractimpl};
// Upgradeable marker
trait UUPSUpgradeable { fn upgrade_to(&self, new_impl: u64); }
#[contract]
pub struct Impl;
impl Impl {
    // BUG: constructor-style fn new sets state that proxy won't see
    pub fn new() -> Self {
        let mut owner = 0u64;
        owner = 42;
        let _ = owner;
        Impl
    }
}
#[contractimpl]
impl Impl {
    pub fn initialize() {}
}
