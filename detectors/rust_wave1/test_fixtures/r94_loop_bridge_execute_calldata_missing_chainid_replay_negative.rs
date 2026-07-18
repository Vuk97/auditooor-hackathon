use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: hash includes chain_id
    pub fn bridge_execute(id: u64, origin: u32, dest: u32, data: u128, chain_id: u64) -> u128 {
        let h = keccak256(&(id, origin, dest, data, chain_id));
        h
    }
}
fn keccak256(_k: &(u64, u32, u32, u128, u64)) -> u128 { 0 }
