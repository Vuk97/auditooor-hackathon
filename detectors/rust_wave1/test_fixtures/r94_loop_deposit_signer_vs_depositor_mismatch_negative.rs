use soroban_sdk::{contract, contractimpl};
#[derive(PartialEq, Eq)]
pub struct Pubkey(pub u64);
#[contract]
pub struct SafeSpokePool;
#[contractimpl]
impl SafeSpokePool {
    // OK: asserts signer == depositor
    pub fn deposit(signer: Pubkey, depositor: Pubkey, amount: u64) {
        require(signer == depositor);
        token::transfer_from(depositor, amount);
    }
}
mod token { pub fn transfer_from(_d: super::Pubkey, _a: u64) {} }
fn require(_: bool) {}
