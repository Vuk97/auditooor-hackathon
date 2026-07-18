use soroban_sdk::{contract, contractimpl};
pub struct PriceFeed { pub price: i128, pub conf: u64 }
#[contract]
pub struct SafeIdx;
#[contractimpl]
impl SafeIdx {
    // OK: .abs() on delta
    pub fn update_index(new_price: i128, current_index: i128, price_feed: PriceFeed) -> bool {
        let delta = (new_price - current_index).abs();
        if delta > price_feed.conf as i128 {
            return false;
        }
        true
    }
}
