use soroban_sdk::{contract, contractimpl, Env};

const BASIS_POINTS: i128 = 10_000;

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: floor-division of flash premium
    pub fn compute_flash_premium(env: Env, amount: i128, fee_bps: i128) -> i128 {
        let premium = amount * fee_bps / BASIS_POINTS;
        premium
    }
}
