use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeQueue;
#[contractimpl]
impl SafeQueue {
    // OK: uses snapshot_tvl from last epoch, not live total_tvl()
    pub fn request_withdraw(shares: u128) -> u128 {
        let tvl = snapshot_tvl();
        let _live = total_tvl();
        let assets_owed = shares * tvl / total_shares();
        assets_owed
    }
}
fn total_tvl() -> u128 { 0 }
fn snapshot_tvl() -> u128 { 0 }
fn total_shares() -> u128 { 1 }
