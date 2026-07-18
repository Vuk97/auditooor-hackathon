use soroban_sdk::{contract, contractimpl};
pub struct PriceUpdate { pub price: i64, pub expo: i32 }
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses .expo to scale
    pub fn get_value(pyth_feed: PriceUpdate, amount: i128) -> i128 {
        let scale = 10_i128.pow((-pyth_feed.expo) as u32);
        amount * pyth_feed.price as i128 / scale
    }
}
