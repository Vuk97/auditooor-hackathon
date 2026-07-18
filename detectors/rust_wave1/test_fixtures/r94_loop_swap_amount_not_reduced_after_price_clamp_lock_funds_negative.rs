use soroban_sdk::{contract, contractimpl};

fn compute_next_price(_a: u128) -> u128 { 0 }
fn compute_used_for_price(_p: u128) -> u128 { 0 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn swap(amount_specified: u128, sqrt_price_limit: u128) -> u128 {
        let mut sqrt_price_next: u128 = compute_next_price(amount_specified);
        let mut amount = amount_specified;
        if sqrt_price_next > sqrt_price_limit {
            sqrt_price_next = sqrt_price_limit;
            let used = compute_used_for_price(sqrt_price_next);
            amount = amount.saturating_sub(used);  // reduce
        }
        return amount;
    }
}
