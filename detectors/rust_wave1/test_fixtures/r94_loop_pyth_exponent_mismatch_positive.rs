use soroban_sdk::{contract, contractimpl};
pub struct PriceUpdate { pub price: i64, pub expo: i32 }
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: reads price.price, never touches .expo
    pub fn get_value(pyth_feed: PriceUpdate, amount: i128) -> i128 {
        amount * pyth_feed.price as i128
    }
}
