use soroban_sdk::{contract, contractimpl};
pub struct Pyth;
impl Pyth { pub fn update_price_feeds(&self, _data: Vec<u8>) {} }
#[contract]
pub struct SafeMarket;
#[contractimpl]
impl SafeMarket {
    // OK: requires msg_amount >= update_fee
    pub fn update_price_feeds(pyth: Pyth, update_data: Vec<u8>, update_fee: u64, msg_amount: u64) {
        require(msg_amount >= update_fee);
        pyth.update_price_feeds(update_data);
    }
}
fn require(_: bool) {}
