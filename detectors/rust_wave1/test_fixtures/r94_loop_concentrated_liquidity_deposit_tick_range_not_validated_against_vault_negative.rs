use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct X;

pub struct Vault {
    pub tick_lower: i32,
    pub tick_upper: i32,
}

pub struct PoolParams {
    tick_lower: i32,
    tick_upper: i32,
    amount: u128,
}

fn pool_mint(_p: &PoolParams) {}

#[contractimpl]
impl X {
    pub fn deposit_fixed(vault: &Vault, tick_lower: i32, tick_upper: i32, amount: u128) {
        assert!(tick_lower >= vault.tick_lower && tick_upper <= vault.tick_upper, "tick range OOB");
        let pool_params = PoolParams { tick_lower: tick_lower, tick_upper: tick_upper, amount };
        pool_mint(&pool_params);
    }
}
