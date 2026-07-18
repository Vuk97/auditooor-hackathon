use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Perp;
#[contractimpl]
impl Perp {
    // BUG: uses orderbook.last_px as perp underlying without oracle fallback
    pub fn get_underlying_price(market_id: u64) -> u128 {
        let _ = market_id;
        orderbook.last_px()
    }
}
struct Ob;
impl Ob { fn last_px(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static orderbook: Ob = Ob;
