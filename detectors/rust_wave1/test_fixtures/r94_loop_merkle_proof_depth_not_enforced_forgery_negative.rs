use soroban_sdk::{contract, contractimpl};
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
const TREE_DEPTH: usize = 32;
#[contract]
pub struct MerkleVerifier;
#[contractimpl]
impl MerkleVerifier {
    // SAFE: enforces proof.len() == TREE_DEPTH before iterating
    pub fn verify_merkle_branch(leaf: [u8; 32], proof: Vec<[u8; 32]>, root: [u8; 32]) -> bool {
        assert!(proof.len() == TREE_DEPTH);
        let mut current = leaf;
        for sib in proof.iter() {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(&current);
            combined.extend_from_slice(sib);
            current = keccak256(&combined);
        }
        current == root
    }
}
