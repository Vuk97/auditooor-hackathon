use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn debt(env: Env) -> i128 {
        // OK: panic on missing, not silent zero
        env.storage()
            .persistent()
            .get::<_, i128>(&1u32)
            .unwrap_or_else(|| panic!("debt missing"))
    }
    pub fn other(x: Option<i128>) -> i128 {
        // OK: unwrap_or(0) NOT on persistent storage
        x.unwrap_or(0)
    }
}
