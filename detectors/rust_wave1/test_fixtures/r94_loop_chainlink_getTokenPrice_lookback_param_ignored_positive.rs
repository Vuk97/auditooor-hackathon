use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lib;
#[contractimpl]
impl Lib {
    // BUG: takes lookback arg but body just calls latest_round_data
    pub fn get_token_price(lookback: u64) -> u128 {
        let _ = lookback;
        aggregator.latest_round_data()
    }
}
struct Agg;
impl Agg { fn latest_round_data(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static aggregator: Agg = Agg;
