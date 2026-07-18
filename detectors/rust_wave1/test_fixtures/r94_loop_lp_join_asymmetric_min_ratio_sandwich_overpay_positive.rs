use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn on_join_pool(token0_in: u128, token1_in: u128, reserve0: u128, reserve1: u128, supply: u128) -> u128 {
        std::cmp::min(token0_in * supply / reserve0, token1_in * supply / reserve1)
    }
}
