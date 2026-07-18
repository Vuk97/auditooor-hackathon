use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeOracle;
#[contractimpl]
impl SafeOracle {
    // OK: price is clamped via MIN_PRICE/MAX_PRICE bounds check
    pub fn get_price() -> u128 {
        let price = aggregator.latest_round_data();
        if price < MIN_PRICE || price > MAX_PRICE { panic!("outlier"); }
        price
    }
}
const MIN_PRICE: u128 = 1;
const MAX_PRICE: u128 = 1_000_000_000;
struct Agg;
impl Agg { fn latest_round_data(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static aggregator: Agg = Agg;
