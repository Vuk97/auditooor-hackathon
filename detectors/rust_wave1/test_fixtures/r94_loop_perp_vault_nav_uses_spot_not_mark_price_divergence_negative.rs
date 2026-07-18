use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

fn get_mark_price() -> u128 { 1_000 }

#[contractimpl]
impl X {
    pub fn compute_nav(position_size: u128) -> u128 {
        let mark_price = get_mark_price();
        position_size * mark_price
    }
}
