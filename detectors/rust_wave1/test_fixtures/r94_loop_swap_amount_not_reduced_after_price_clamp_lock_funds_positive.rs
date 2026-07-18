use soroban_sdk::{contract, contractimpl};

fn compute_next_price(_a: u128) -> u128 { 0 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn swap(amount_specified: u128, sqrt_price_limit: u128) -> u128 {
        let mut sqrt_price_next: u128 = compute_next_price(amount_specified);
        if sqrt_price_next > sqrt_price_limit {
            sqrt_price_next = sqrt_price_limit;  // clamp
        }
        return amount_specified;  // BUG: didn't subtract unused
    }
}
