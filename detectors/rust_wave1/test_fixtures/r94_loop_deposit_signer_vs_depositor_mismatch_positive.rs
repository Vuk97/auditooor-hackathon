use soroban_sdk::{contract, contractimpl};
pub struct Pubkey;
#[contract]
pub struct SpokePool;
#[contractimpl]
impl SpokePool {
    // BUG: transfer_from depositor while signer is separate; no equality check
    pub fn deposit(signer: Pubkey, depositor: Pubkey, amount: u64) {
        token::transfer_from(depositor, amount);
    }
    pub fn deposit_on_behalf(authority: Pubkey, depositor: Pubkey, amount: u64) {
        spl_token::transfer_from(depositor, amount);
    }
}
mod token { pub fn transfer_from(_d: super::Pubkey, _a: u64) {} }
mod spl_token { pub fn transfer_from(_d: super::Pubkey, _a: u64) {} }
