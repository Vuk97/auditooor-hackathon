use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLendingPool;
#[contractimpl]
impl SafeLendingPool {
    // OK: require feed_id matches the configured expected_feed
    pub fn borrow(asset: u128, feed_id: u128, amount: u128, expected_feed: u128) -> u128 {
        require(feed_id == expected_feed);
        let price = pyth::get_price_feed(feed_id);
        amount * price
    }
    pub fn borrow_assert(asset: u128, feed_id: u128, amount: u128, canonical_feed: u128) -> u128 {
        assert_eq!(feed_id, canonical_feed);
        let price = pyth::get_price_feed(feed_id);
        amount * price
    }
}
fn require(_c: bool) {}
mod pyth { pub fn get_price_feed(_f: u128) -> u128 { 1 } }
