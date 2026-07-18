use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: rounds toward user (standard / is floor div). Should be mul_div_up.
    pub fn ask_exact_amount_out(amount_out: u128, reserves: u128, fee: u128) -> u128 {
        let numerator = amount_out * 1000;
        let denominator = reserves - amount_out;
        numerator / denominator
    }

    // BUG: mul_div (floor) where the pool should round up
    pub fn calc_amount_out(amount_in: u128, reserves: u128) -> u128 {
        mul_div(amount_in, reserves, amount_in + 1)
    }
}
fn mul_div(a: u128, b: u128, c: u128) -> u128 { a * b / c }
