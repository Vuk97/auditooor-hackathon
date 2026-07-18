use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Marketplace;
#[contractimpl]
impl Marketplace {
    // BUG: checks listing validity via shared balance_of(marketplace, token_id)
    pub fn _is_listing_valid(listing_token_id: u64, listing_amount: u128) -> bool {
        let bal = balance_of(marketplace, listing_token_id);
        bal >= listing_amount
    }
}
fn balance_of(_m: u64, _t: u64) -> u128 { 0 }
#[allow(non_upper_case_globals)]
static marketplace: u64 = 0;
