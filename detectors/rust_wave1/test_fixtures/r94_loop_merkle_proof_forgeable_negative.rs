use soroban_sdk::{contract, contractimpl};
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;
#[contract]
pub struct SafeVerifier;
#[contractimpl]
impl SafeVerifier {
    // OK: domain tags separate leaf from node
    pub fn verify_proof(leaf: [u8; 32], proof: Vec<[u8; 32]>, root: [u8; 32]) -> bool {
        let mut combined = Vec::with_capacity(33);
        combined.push(LEAF_TAG);
        combined.extend_from_slice(&leaf);
        let mut current = keccak256(&combined);
        for sib in proof {
            let mut combined = Vec::with_capacity(65);
            combined.push(NODE_TAG);
            combined.extend_from_slice(&current);
            combined.extend_from_slice(&sib);
            current = keccak256(&combined);
        }
        current == root
    }
}
