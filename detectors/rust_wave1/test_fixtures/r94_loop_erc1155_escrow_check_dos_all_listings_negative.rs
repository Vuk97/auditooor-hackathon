use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMarketplace;
#[contractimpl]
impl SafeMarketplace {
    // OK: uses per-listing dedicated escrow instead of shared balance
    pub fn _is_listing_valid(listing_id: u64, listing_amount: u128) -> bool {
        let reserved = listing_escrow[listing_id];
        reserved >= listing_amount
    }
}
#[allow(non_upper_case_globals)]
static mut listing_escrow: [u128; 16] = [0; 16];
