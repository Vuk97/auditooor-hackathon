use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Auction;
#[contractimpl]
impl Auction {
    // BUG: dutch auction stores pending bid without immediate settle
    pub fn bid(listing_id: u64, bid_amount: u128) {
        let _ = bid_amount;
        let is_dutch = true;
        if is_dutch {
            best_bid_for_listing[listing_id] = bid_amount;
        }
    }
}
#[allow(non_upper_case_globals)]
static mut best_bid_for_listing: [u128; 16] = [0; 16];
