use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeChallenger;
#[contractimpl]
impl SafeChallenger {
    // OK: storage_root assigned from computed root
    pub fn handle_tree(leaves: Vec<[u8; 32]>) -> [u8; 32] {
        let mut storage_root: [u8; 32] = [0; 32];
        storage_root = merkle_root(leaves);
        storage_root
    }
}
fn merkle_root(_l: Vec<[u8; 32]>) -> [u8; 32] { [0; 32] }
