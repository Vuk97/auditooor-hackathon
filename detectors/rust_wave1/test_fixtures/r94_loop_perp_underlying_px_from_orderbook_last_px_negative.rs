use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePerp;
#[contractimpl]
impl SafePerp {
    // OK: uses oracle_feed with fallback, not orderbook last_px
    pub fn get_underlying_price(market_id: u64) -> u128 {
        let _ = market_id;
        let _ = orderbook.last_px();
        oracle_feed.get()
    }
}
struct Ob;
impl Ob { fn last_px(&self) -> u128 { 0 } }
struct Oracle;
impl Oracle { fn get(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static orderbook: Ob = Ob;
#[allow(non_upper_case_globals)]
static oracle_feed: Oracle = Oracle;
