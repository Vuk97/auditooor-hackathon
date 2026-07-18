use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn forward(domain_separator: [u8; 32], hash: [u8; 32], sig: Vec<u8>) {
        let signer = ecdsa_recover_with_domain(domain_separator, hash, &sig);
        let _ = signer;
    }
}

fn ecdsa_recover_with_domain(_d: [u8; 32], _h: [u8; 32], _s: &[u8]) -> [u8; 20] { [0; 20] }
