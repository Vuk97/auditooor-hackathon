use soroban_sdk::{contract, contractimpl};
trait UUPSUpgradeable { fn authorize_upgrade(&self, new_impl: u64); }
#[contract]
pub struct SafeImpl;
#[contractimpl]
impl SafeImpl {
    // OK: _disable_initializers() called at construction / init-block
    pub fn initialize(owner: u64) {
        let _ = owner;
    }
    fn authorize_upgrade(_new_impl: u64) {}
}
fn _disable_initializers() {}
// constructor equivalent that runs _disable_initializers at deploy
#[allow(dead_code)]
fn ctor() { _disable_initializers(); }
