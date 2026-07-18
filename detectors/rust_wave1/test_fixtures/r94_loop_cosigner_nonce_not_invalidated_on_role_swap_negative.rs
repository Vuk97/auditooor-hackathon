use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeWallet;
#[contractimpl]
impl SafeWallet {
    // OK: bumps cosigner_nonce on role swap
    pub fn set_cosigner(new_cosigner: u64) {
        let mut cosigner = 0u64;
        cosigner = new_cosigner;
        let _ = cosigner;
        let mut cosigner_nonce = 0u64;
        cosigner_nonce += 1;
        let _ = cosigner_nonce;
    }
}
