use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Challenger;
#[contractimpl]
impl Challenger {
    // BUG: storage_root declared as [0;32] default, never assigned
    pub fn handle_tree(leaves: Vec<[u8; 32]>) -> [u8; 32] {
        let storage_root: [u8; 32] = [0; 32];
        // compute and forget
        let _computed: [u8; 32] = merkle_root(leaves);
        storage_root
    }
}
fn merkle_root(_l: Vec<[u8; 32]>) -> [u8; 32] { [0; 32] }
