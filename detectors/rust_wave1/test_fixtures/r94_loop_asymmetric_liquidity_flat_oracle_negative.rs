use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: one-sided branch applies dynamic_spread proportional to size
    pub fn swap(reserve_a: u128, reserve_b: u128, amount: u128) -> u128 {
        if reserve_b == 0 {
            let oracle_price = get_oracle_price();
            let impact = dynamic_spread(amount);
            return amount * oracle_price - impact;
        }
        amount * reserve_b / reserve_a
    }
    // OK: refuses to quote at all when one side is empty
    pub fn quote_exact(reserve_in: u128, reserve_out: u128, amount_in: u128) -> u128 {
        if reserve_in == 0 {
            panic!("asymmetric liquidity");
        }
        amount_in * reserve_out / reserve_in
    }
}
fn get_oracle_price() -> u128 { 1 }
fn dynamic_spread(_amount: u128) -> u128 { 0 }
