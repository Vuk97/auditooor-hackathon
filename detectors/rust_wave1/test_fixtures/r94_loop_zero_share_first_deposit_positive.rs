use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: share-ratio math, no zero guard on share_amount
    pub fn request_withdraw(share_amount: u128, total_shares: u128, total_assets: u128) -> u128 {
        share_amount * total_assets / total_shares
    }
    // BUG: deposit with ratio, no zero guard
    pub fn deposit(amount: u128, total_shares: u128, total_assets: u128) -> u128 {
        amount * total_shares / total_assets
    }
}
