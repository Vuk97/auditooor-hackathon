use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Wallet;
#[contractimpl]
impl Wallet {
    // BUG: swaps cosigner without bumping cosigner_nonce
    pub fn set_cosigner(new_cosigner: u64) {
        let mut cosigner = 0u64;
        cosigner = new_cosigner;
        let _ = cosigner;
    }
}
