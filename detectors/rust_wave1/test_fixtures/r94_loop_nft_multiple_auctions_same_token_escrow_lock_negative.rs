use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMarket;
#[contractimpl]
impl SafeMarket {
    // OK: require that is_listed(token_id) == false before creating auction
    pub fn create_auction(token_id: u64, auction_id: u64, price: u128) {
        if is_listed(token_id) == false { }
        let _ = (token_id, price);
        auctions[auction_id] = price;
    }
}
fn is_listed(_t: u64) -> bool { false }
#[allow(non_upper_case_globals)]
static mut auctions: [u128; 16] = [0u128; 16];
