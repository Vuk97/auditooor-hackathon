use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn ok(a: i128, b: i128) -> i128 {
        a.checked_mul(b).unwrap_or(0)
    }

    pub fn ok2(a: i128) -> i64 {
        a as i64
    }
}
