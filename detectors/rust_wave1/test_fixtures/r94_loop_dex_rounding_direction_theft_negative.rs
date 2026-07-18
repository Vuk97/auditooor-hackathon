use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: uses mul_div_up for pool-favorable rounding
    pub fn ask_exact_amount_out(amount_out: u128, reserves: u128, fee: u128) -> u128 {
        mul_div_up(amount_out, 1000, reserves - amount_out)
    }

    // OK: explicit ceil_div
    pub fn calc_amount_out(amount_in: u128, reserves: u128) -> u128 {
        ceil_div(amount_in * reserves, amount_in + 1)
    }
}
fn mul_div_up(a: u128, b: u128, c: u128) -> u128 { (a * b + c - 1) / c }
fn ceil_div(a: u128, b: u128) -> u128 { (a + b - 1) / b }
