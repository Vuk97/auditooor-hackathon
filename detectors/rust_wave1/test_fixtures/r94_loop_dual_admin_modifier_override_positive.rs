use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SeaDrop;
#[contractimpl]
impl SeaDrop {
    // BUG: only_owner_or_admin modifier — admin can override owner's signer
    pub fn update_signer(new_signer: u64) {
        only_owner_or_admin();
        storage().set(new_signer);
    }
}
fn only_owner_or_admin() {}
fn storage() -> Store { Store }
struct Store; impl Store { fn set(&self, _v: u64) {} }
