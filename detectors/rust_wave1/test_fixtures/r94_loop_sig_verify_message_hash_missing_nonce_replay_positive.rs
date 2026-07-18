use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn update_keys(message_hash: [u8; 32], sig: Vec<u8>) {
        let signer = ecdsa_recover(message_hash, &sig);
        let _ = signer;
    }
}

fn ecdsa_recover(_h: [u8; 32], _s: &[u8]) -> [u8; 20] { [0; 20] }
