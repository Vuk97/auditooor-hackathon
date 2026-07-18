use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct World;
#[contractimpl]
impl World {
    // BUG: takes both name and hash but never cross-validates
    pub fn register_model(name: String, namespace_hash: [u8; 32], model: u64) {
        persist_model(name, namespace_hash, model);
    }
}
fn persist_model(_n: String, _h: [u8; 32], _m: u64) {}
