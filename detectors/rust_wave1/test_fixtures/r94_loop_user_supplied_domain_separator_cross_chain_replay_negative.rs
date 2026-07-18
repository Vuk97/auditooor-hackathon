use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn forward(hash: [u8; 32], sig: Vec<u8>) {
        let domain = DOMAIN_SEPARATOR();
        let signer = ecdsa_recover_with_domain(domain, hash, &sig);
        let _ = signer;
    }
}

fn DOMAIN_SEPARATOR() -> [u8; 32] { [0; 32] }
fn ecdsa_recover_with_domain(_d: [u8; 32], _h: [u8; 32], _s: &[u8]) -> [u8; 20] { [0; 20] }
