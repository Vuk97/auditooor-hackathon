use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
pub struct Ecdsa;
impl Ecdsa {
    pub fn recover(_hash: [u8; 32], _sig: &[u8]) -> Address { [0; 20] }
}
pub struct Wallet { owner: Address }
#[contract]
pub struct WalletImpl;
#[contractimpl]
impl WalletImpl {
    // BUG: no zero-address check after ECDSA::recover
    pub fn validate_signature(wallet: &Wallet, hash: [u8; 32], sig: Vec<u8>) -> bool {
        let signer = Ecdsa::recover(hash, &sig);
        signer == wallet.owner
    }
}
