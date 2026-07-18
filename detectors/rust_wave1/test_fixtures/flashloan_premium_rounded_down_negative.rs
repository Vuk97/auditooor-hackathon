use soroban_sdk::{contract, contractimpl, Env};

const BASIS_POINTS: i128 = 10_000;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: ceil-division ensures protocol never under-charges
    pub fn compute_flash_premium(env: Env, amount: i128, fee_bps: i128) -> i128 {
        let premium = (amount * fee_bps + BASIS_POINTS - 1) / BASIS_POINTS;
        premium
    }
}
