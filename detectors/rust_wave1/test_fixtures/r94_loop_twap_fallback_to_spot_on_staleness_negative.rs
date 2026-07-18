use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFeed;
#[contractimpl]
impl SafeFeed {
    // OK: reverts on twap staleness instead of falling back to spot
    pub fn get_price() -> u128 {
        let twap_ts = twap_timestamp();
        if twap_ts + 3600 < now() {
            panic!("twap stale");
        }
        twap_value()
    }
}
fn twap_timestamp() -> u64 { 0 }
fn twap_value() -> u128 { 0 }
fn now() -> u64 { 0 }
