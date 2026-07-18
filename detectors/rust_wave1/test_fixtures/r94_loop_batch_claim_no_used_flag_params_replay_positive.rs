use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn batch_claim(claim_params: Vec<u8>, merkle_proof: Vec<[u8; 32]>) {
        assert!(verify_proof(&merkle_proof, &claim_params), "bad proof");
        pay_out(&claim_params);
    }
}

fn verify_proof(_p: &Vec<[u8; 32]>, _c: &Vec<u8>) -> bool { true }
fn pay_out(_p: &Vec<u8>) {}
