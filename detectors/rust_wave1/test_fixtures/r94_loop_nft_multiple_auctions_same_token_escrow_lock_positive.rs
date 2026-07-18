use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Market;
#[contractimpl]
impl Market {
    // BUG: creates auction entry without checking if token already listed
    pub fn create_auction(token_id: u64, auction_id: u64, price: u128) {
        let _ = (token_id, price);
        auctions[auction_id] = price;
    }
}
#[allow(non_upper_case_globals)]
static mut auctions: [u128; 16] = [0u128; 16];
