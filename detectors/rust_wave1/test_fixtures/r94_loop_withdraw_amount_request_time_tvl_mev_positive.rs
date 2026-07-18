use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Queue;
#[contractimpl]
impl Queue {
    // BUG: computes assets owed from live total_tvl() at request time
    pub fn request_withdraw(shares: u128) -> u128 {
        let tvl = total_tvl();
        let assets_owed = shares * tvl / total_shares();
        assets_owed
    }
}
fn total_tvl() -> u128 { 0 }
fn total_shares() -> u128 { 1 }
