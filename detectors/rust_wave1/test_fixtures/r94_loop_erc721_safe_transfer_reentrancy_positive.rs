use soroban_sdk::{contract, contractimpl};
pub struct Nft;
impl Nft { pub fn safe_transfer_from(&self, _from: u64, _to: u64, _id: u64) {} }
#[contract]
pub struct Escrow;
#[contractimpl]
impl Escrow {
    // BUG: safe_transfer_from then state mutation, no guard
    pub fn deposit(nft: Nft, user: u64, id: u64, balances: &mut std::collections::HashMap<u64, u128>) {
        nft.safe_transfer_from(user, 0, id);
        balances.insert(user, 1u128);
    }
}
