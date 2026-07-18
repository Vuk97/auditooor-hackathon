use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: uses `<=` on health_factor
    pub fn liquidate(env: Env, user: Address, debt: i128) -> i128 {
        let health_factor: i128 = compute_hf(&env, &user);
        if health_factor <= 1_000_000_000_000_000_000 {
            return debt / 2;
        }
        0
    }

    // SAFE: uses `>=` on close_factor
    pub fn liquidate_partial(env: Env, user: Address, repay: i128) -> i128 {
        let close_factor: i128 = 5000;
        if repay >= close_factor {
            panic_with_error!(&env, 1u32);
        }
        repay
    }
}

fn compute_hf(_: &Env, _: &Address) -> i128 { 0 }
