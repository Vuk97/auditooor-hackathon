use soroban_sdk::{contract, contractimpl};

fn sum_all_makers_skew() -> i128 { 0 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn compute_funding_rate(total_notional: i128) -> i128 {
        let total_market_skew = sum_all_makers_skew();
        let rate = total_market_skew * 100 / total_notional;
        rate
    }
}
