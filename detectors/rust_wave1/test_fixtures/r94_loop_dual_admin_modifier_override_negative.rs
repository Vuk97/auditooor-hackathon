use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSeaDrop;
#[contractimpl]
impl SafeSeaDrop {
    // OK: only_owner modifier, not dual-auth
    pub fn update_signer(new_signer: u64) {
        only_owner();
        storage().set(new_signer);
    }
}
fn only_owner() {}
fn storage() -> Store { Store }
struct Store; impl Store { fn set(&self, _v: u64) {} }
