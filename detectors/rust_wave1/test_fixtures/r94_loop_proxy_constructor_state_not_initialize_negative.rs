use soroban_sdk::{contract, contractimpl};
// Upgradeable marker
trait UUPSUpgradeable { fn upgrade_to(&self, new_impl: u64); }
#[contract]
pub struct SafeImpl;
#[contractimpl]
impl SafeImpl {
    // OK: state set only inside initialize(), not constructor
    pub fn initialize() {
        let mut owner = 0u64;
        owner = 42;
        let _ = owner;
    }
}
