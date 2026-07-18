use soroban_sdk::{contract, contractimpl};

pub mod ECDSA {
    pub fn recover(_hash: [u8; 32], _v: u8, _r: [u8; 32], _s: [u8; 32]) -> [u8; 20] { [0; 20] }
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn verify_signature(hash: [u8; 32], v: u8, r: [u8; 32], s: [u8; 32]) -> [u8; 20] {
        ECDSA::recover(hash, v, r, s)
    }
}
