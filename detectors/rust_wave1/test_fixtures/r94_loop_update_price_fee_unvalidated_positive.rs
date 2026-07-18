use soroban_sdk::{contract, contractimpl};
pub struct Pyth;
impl Pyth { pub fn update_price_feeds(&self, _data: Vec<u8>) {} }
#[contract]
pub struct Market;
#[contractimpl]
impl Market {
    // BUG: no msg_amount vs update_fee check
    pub fn update_price_feeds(pyth: Pyth, update_data: Vec<u8>, update_fee: u64) {
        let _fee = update_fee;
        pyth.update_price_feeds(update_data);
    }
}
