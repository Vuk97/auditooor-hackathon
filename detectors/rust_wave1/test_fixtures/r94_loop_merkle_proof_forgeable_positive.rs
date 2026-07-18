use soroban_sdk::{contract, contractimpl};
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
#[contract]
pub struct Verifier;
#[contractimpl]
impl Verifier {
    // BUG: hashes leaf + siblings with no domain tag
    pub fn verify_proof(leaf: [u8; 32], proof: Vec<[u8; 32]>, root: [u8; 32]) -> bool {
        let mut current = leaf;
        for sib in proof {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&current);
            combined.extend_from_slice(&sib);
            current = keccak256(&combined);
        }
        current == root
    }
}
