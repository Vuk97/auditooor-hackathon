use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Airdrop;
#[contractimpl]
impl Airdrop {
    // BUG: verifies merkle proof but no used_leaves[leaf] tracking
    pub fn redeem(leaf: u128, proof: u128, amount: u128) -> u128 {
        if !MerkleProof.verify(leaf, proof, root()) { panic!(); }
        token_transfer(caller(), amount);
        amount
    }
}
struct MP;
impl MP { fn verify(&self, _l: u128, _p: u128, _r: u128) -> bool { true } }
#[allow(non_upper_case_globals)]
static MerkleProof: MP = MP;
fn root() -> u128 { 0 }
fn token_transfer(_to: u64, _a: u128) {}
fn caller() -> u64 { 0 }
