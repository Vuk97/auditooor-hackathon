use soroban_sdk::{contract, contractimpl};

fn st_eth_per_token() -> u128 { 1_100_000_000_000_000_000 }
fn get_price_of_steth() -> u128 { 999_000_000_000_000_000 }

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn eth_per_derivative(amount: u128) -> u128 {
        let rate = st_eth_per_token();
        let steth_eth_oracle_price = get_price_of_steth();
        amount * rate * steth_eth_oracle_price / 1_000_000_000_000_000_000_000_000_000_000_000_000
    }
}
