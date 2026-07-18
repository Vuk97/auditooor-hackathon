use soroban_sdk::{contract, contractimpl};

fn st_eth_per_token() -> u128 { 1_100_000_000_000_000_000 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn eth_per_derivative(amount: u128) -> u128 {
        let rate = st_eth_per_token();
        amount * rate / 1_000_000_000_000_000_000
    }
}
