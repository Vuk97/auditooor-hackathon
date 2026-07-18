use soroban_sdk::{contract, contractimpl};
fn keccak256(_: &[u8]) -> [u8; 32] { [0; 32] }
mod borsh { pub fn to_vec<T>(_: &T) -> Vec<u8> { vec![] } }
#[contract]
pub struct Unlock;
#[contractimpl]
impl Unlock {
    // Site A: borsh-derived hash
    pub fn init_compact_unlock(items: Vec<u64>) -> [u8; 32] {
        let payload = borsh::to_vec(&items);
        keccak256(&payload)
    }
    // Site B: raw-concat hash of the SAME logical data, different derivation
    pub fn verify_compact_unlock(items: Vec<u64>, a: u64, b: u64, c: u64) -> [u8; 32] {
        let payload = &[a.to_le_bytes(), b.to_le_bytes(), c.to_le_bytes()];
        keccak256(&payload.concat())
    }
}
