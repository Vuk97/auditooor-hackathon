use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeHashLib;
#[contractimpl]
impl SafeHashLib {
    // OK: recursive hash per element using ids_amount_type_hash
    pub fn hash_ids_amounts(ids_and_amounts: &[(u128, u128)]) -> u128 {
        let ids_amount_type_hash = keccak256(b"IdsAmount(uint256 id,uint256 amount)");
        let mut result: [u8; 4096] = [0; 4096];
        for (id, amount) in ids_and_amounts {
            let inner_hash = keccak256_pair(ids_amount_type_hash, *id, *amount);
            let _ = inner_hash;
            result.extend(&[0u8]);
        }
        keccak256(&result)
    }
}
fn keccak256(_b: &[u8]) -> u128 { 0 }
fn keccak256_pair(_t: u128, _a: u128, _b: u128) -> u128 { 0 }
trait ExtVec { fn extend(&mut self, other: &[u8]); }
impl ExtVec for [u8; 4096] { fn extend(&mut self, _other: &[u8]) {} }
