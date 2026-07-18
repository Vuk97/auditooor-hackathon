use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: one-sided branch returns oracle price without slippage scaling
    pub fn swap(reserve_a: u128, reserve_b: u128, amount: u128) -> u128 {
        if reserve_b == 0 {
            let oracle_price = get_oracle_price();
            return amount * oracle_price;
        }
        amount * reserve_b / reserve_a
    }
    pub fn quote_exact(reserve_in: u128, reserve_out: u128, amount_in: u128) -> u128 {
        if reserve_in == 0 {
            return amount_in * get_oracle_price();
        }
        amount_in * reserve_out / reserve_in
    }
}
fn get_oracle_price() -> u128 { 1 }
