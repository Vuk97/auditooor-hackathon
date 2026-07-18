use soroban_sdk::{contract, contractimpl};
pub struct Chainlink;
impl Chainlink { pub fn latest_round_data(&self) -> i128 { 0 } }
#[contract]
pub struct Oracle;
#[contractimpl]
impl Oracle {
    // BUG: hardcoded 1e8 scale
    pub fn get_price(feed: Chainlink) -> u128 {
        let p = feed.latest_round_data();
        (p as u128) * 1_00_000_000
    }
}
