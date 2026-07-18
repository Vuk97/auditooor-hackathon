use soroban_sdk::{contract, contractimpl};
pub struct PriceFeed { pub price: i128, pub conf: u64 }
#[contract]
pub struct Idx;
#[contractimpl]
impl Idx {
    // BUG: signed compare, no .abs()
    pub fn update_index(new_price: i128, current_index: i128, price_feed: PriceFeed) -> bool {
        let delta = new_price - current_index;
        if delta > price_feed.conf as i128 {
            return false;
        }
        true
    }
}
