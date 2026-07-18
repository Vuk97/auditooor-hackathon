use soroban_sdk::{contract, contractimpl};
pub struct Chainlink;
impl Chainlink {
    pub fn latest_round_data(&self) -> i128 { 0 }
    pub fn decimals(&self) -> u32 { 8 }
}
#[contract]
pub struct SafeOracle;
#[contractimpl]
impl SafeOracle {
    // OK: uses feed.decimals() dynamically
    pub fn get_price(feed: Chainlink) -> u128 {
        let p = feed.latest_round_data();
        let d = feed.decimals();
        (p as u128) * 10u128.pow(d)
    }
}
