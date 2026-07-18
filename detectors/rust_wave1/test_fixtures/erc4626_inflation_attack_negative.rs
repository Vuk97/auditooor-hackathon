use soroban_sdk::{contract, contractimpl, Address, Env};

const VIRTUAL_SHARES: i128 = 1_000_000;
const VIRTUAL_ASSETS: i128 = 1;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn total_supply(_env: Env) -> i128 { 0 }
    pub fn total_assets(_env: Env) -> i128 { 0 }

    pub fn deposit(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        let total_supply = Self::total_supply(env.clone()) + VIRTUAL_SHARES;
        let total_assets = Self::total_assets(env.clone()) + VIRTUAL_ASSETS;
        let shares: i128 = amount * total_supply / total_assets;
        shares
    }
}
