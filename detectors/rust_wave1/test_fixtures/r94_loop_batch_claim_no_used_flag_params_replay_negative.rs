use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn batch_claim(claim_params: Vec<u8>, merkle_proof: Vec<[u8; 32]>) {
        assert!(verify_proof(&merkle_proof, &claim_params), "bad proof");
        let params_hash = hash_params(&claim_params);
        assert!(!is_consumed(&params_hash), "already claimed");
        mark_consumed(&params_hash);
        pay_out(&claim_params);
    }
}

fn hash_params(_c: &Vec<u8>) -> [u8; 32] { [0; 32] }
fn is_consumed(_h: &[u8; 32]) -> bool { false }
fn mark_consumed(_h: &[u8; 32]) {}
fn verify_proof(_p: &Vec<[u8; 32]>, _c: &Vec<u8>) -> bool { true }
fn pay_out(_p: &Vec<u8>) {}
