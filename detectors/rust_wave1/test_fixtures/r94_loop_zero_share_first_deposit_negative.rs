use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: zero-guard
    pub fn request_withdraw(share_amount: u128, total_shares: u128, total_assets: u128) -> u128 {
        require(share_amount > 0);
        share_amount * total_assets / total_shares
    }
    pub fn deposit(amount: u128, total_shares: u128, total_assets: u128) -> u128 {
        if amount == 0 { return 0; }
        amount * total_shares / total_assets
    }
}
fn require(_c: bool) {}
