use soroban_sdk::{contract, contractimpl};
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
mod borsh { pub fn to_vec<T>(_: &T) -> Vec<u8> { vec![] } }
#[contract]
pub struct SafeUnlock;
#[contractimpl]
impl SafeUnlock {
    // OK: both sites go through a shared helper
    pub fn init_compact_unlock(items: Vec<u64>) -> [u8; 32] {
        compute_payload_hash(&items)
    }
    pub fn verify_compact_unlock(items: Vec<u64>) -> [u8; 32] {
        compute_payload_hash(&items)
    }
}
fn compute_payload_hash(items: &Vec<u64>) -> [u8; 32] {
    let payload = borsh::to_vec(items);
    keccak256(&payload)
}
