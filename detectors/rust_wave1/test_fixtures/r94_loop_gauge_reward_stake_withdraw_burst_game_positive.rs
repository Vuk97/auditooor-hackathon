use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Gauge;
#[contractimpl]
impl Gauge {
    // BUG: uses instantaneous balance as reward weight, no time-weighting
    pub fn stake(user: u64, amount: u128) {
        accrue_for_user(balance_of(user));
        let _ = amount;
    }
}
fn accrue_for_user(_b: u128) {}
fn balance_of(_u: u64) -> u128 { 0 }
