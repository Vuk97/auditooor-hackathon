use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct TaxToken;
#[contractimpl]
impl TaxToken {
    // BUG: refund uses post-fee amount (balance delta, not input)
    pub fn refund(user: u64, balance_before: u128) -> u128 {
        let amount_after_fee = balance_of(user) - balance_before;
        let refund = amount_after_fee * 5 / 100;
        refund
    }
}
fn balance_of(_u: u64) -> u128 { 0 }
