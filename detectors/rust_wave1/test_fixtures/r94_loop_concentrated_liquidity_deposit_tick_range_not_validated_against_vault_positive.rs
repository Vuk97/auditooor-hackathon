use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

pub struct PoolParams {
    tick_lower: i32,
    tick_upper: i32,
    amount: u128,
}

fn pool_mint(_p: &PoolParams) {}

#[contractimpl]
impl X {
    pub fn deposit_fixed(tick_lower: i32, tick_upper: i32, amount: u128) {
        let pool_params = PoolParams { tick_lower: tick_lower, tick_upper: tick_upper, amount };
        pool_mint(&pool_params);
    }
}
