use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: dedup hash omits chain_id
    pub fn bridge_execute(id: u64, origin: u32, dest: u32, data: u128) -> u128 {
        let h = keccak256(&(id, origin, dest, data));
        h
    }
}
fn keccak256(_k: &(u64, u32, u32, u128)) -> u128 { 0 }
