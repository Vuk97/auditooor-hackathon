use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Oracle;
#[contractimpl]
impl Oracle {
    // BUG: passes latest_round_data through without any bound check
    pub fn get_price() -> u128 {
        aggregator.latest_round_data()
    }
}
struct Agg;
impl Agg { fn latest_round_data(&self) -> u128 { 0 } }
#[allow(non_upper_case_globals)]
static aggregator: Agg = Agg;
