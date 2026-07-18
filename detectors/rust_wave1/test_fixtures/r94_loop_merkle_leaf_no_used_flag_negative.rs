use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeAirdrop;
#[contractimpl]
impl SafeAirdrop {
    // OK: checks + inserts used_leaves after proof verification
    pub fn redeem(leaf: u128, proof: u128, amount: u128) -> u128 {
        if !MerkleProof.verify(leaf, proof, root()) { panic!(); }
        if used_leaves().get(&leaf) { panic!("replay"); }
        used_leaves().insert(leaf);
        token_transfer(caller(), amount);
        amount
    }
}
struct MP;
impl MP { fn verify(&self, _l: u128, _p: u128, _r: u128) -> bool { true } }
#[allow(non_upper_case_globals)]
static MerkleProof: MP = MP;
fn root() -> u128 { 0 }
fn used_leaves() -> Used { Used }
struct Used;
impl Used {
    fn get(&self, _l: &u128) -> bool { false }
    fn insert(&self, _l: u128) {}
}
fn token_transfer(_to: u64, _a: u128) {}
fn caller() -> u64 { 0 }
