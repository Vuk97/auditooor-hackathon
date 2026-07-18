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
    // SAFE: asserts signer != address(0) before owner comparison
    pub fn validate_signature(wallet: &Wallet, hash: [u8; 32], sig: Vec<u8>) -> bool {
        let signer = Ecdsa::recover(hash, &sig);
        assert!(signer != [0u8; 20], "recovered signer cannot be zero address");
        signer == wallet.owner
    }
}
