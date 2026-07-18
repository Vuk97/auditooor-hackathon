use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeGauge;
#[contractimpl]
impl SafeGauge {
    // OK: uses time_weighted balance (ve-style) for reward weight
    pub fn stake(user: u64, amount: u128) {
        let w = time_weighted_balance(user);
        accrue_for_user(w);
        let _ = amount;
    }
}
fn accrue_for_user(_b: u128) {}
fn time_weighted_balance(_u: u64) -> u128 { 0 }
