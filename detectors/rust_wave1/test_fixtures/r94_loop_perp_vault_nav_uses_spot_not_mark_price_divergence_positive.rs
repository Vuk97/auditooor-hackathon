use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

fn oracle_spot_price() -> u128 { 1_000 }

#[contractimpl]
impl X {
    pub fn compute_nav(position_size: u128) -> u128 {
        let price = oracle_spot_price();
        position_size * price
    }
}
