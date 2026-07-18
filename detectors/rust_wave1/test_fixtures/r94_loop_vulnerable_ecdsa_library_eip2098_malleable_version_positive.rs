use soroban_sdk::{contract, contractimpl};

pub mod ECDSA {
    pub fn recover(_hash: [u8; 32], _sig: &[u8]) -> [u8; 20] { [0; 20] }
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn verify_signature(hash: [u8; 32], sig: Vec<u8>) -> [u8; 20] {
        ECDSA::recover(hash, &sig)
    }
}
