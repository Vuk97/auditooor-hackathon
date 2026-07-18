use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct HashLib;
#[contractimpl]
impl HashLib {
    // BUG: hashes nested ids_and_amounts via flat concat instead of recursive
    pub fn hash_ids_amounts(ids_and_amounts: &[(u128, u128)]) -> u128 {
        let mut result: [u8; 4096] = [0; 4096];
        for tuple in ids_and_amounts {
            let _ = tuple;
            result.extend(&[0u8]);
        }
        keccak256(&result)
    }
}
fn keccak256(_b: &[u8]) -> u128 { 0 }
trait ExtVec { fn extend(&mut self, other: &[u8]); }
impl ExtVec for [u8; 4096] { fn extend(&mut self, _other: &[u8]) {} }
