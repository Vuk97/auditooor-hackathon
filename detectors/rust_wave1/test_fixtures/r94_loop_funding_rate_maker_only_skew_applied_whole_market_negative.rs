use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMarket;
#[contractimpl]
impl SafeMarket {
    // OK: funding rate from aggregate_skew across all makers
    pub fn update_funding() {
        let skew = aggregate_skew();
        let rate = skew / 100;
        for pos in positions() {
            apply_funding(pos, rate);
        }
    }
}
fn aggregate_skew() -> u128 { 0 }
fn positions() -> Vec<u64> { Vec::new() }
fn apply_funding(_p: u64, _r: u128) {}
