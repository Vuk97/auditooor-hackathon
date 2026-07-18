use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Feed;
#[contractimpl]
impl Feed {
    // BUG: falls back to spot_price when twap is stale
    pub fn get_price() -> u128 {
        let twap_ts = twap_timestamp();
        if twap_ts + 3600 < now() {
            return spot_price();
        }
        twap_value()
    }
}
fn twap_timestamp() -> u64 { 0 }
fn twap_value() -> u128 { 0 }
fn spot_price() -> u128 { 0 }
fn now() -> u64 { 0 }
