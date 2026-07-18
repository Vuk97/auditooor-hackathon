use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct LendingPool;
#[contractimpl]
impl LendingPool {
    // BUG: fetches price via caller-supplied feed_id, no equality check
    pub fn borrow(asset: u128, feed_id: u128, amount: u128) -> u128 {
        let price = pyth::get_price_feed(feed_id);
        amount * price
    }
}
mod pyth { pub fn get_price_feed(_f: u128) -> u128 { 1 } }
