use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    pub fn total_supply(_env: Env) -> i128 { 0 }
    pub fn total_assets(_env: Env) -> i128 { 0 }

    // VULN: naive 4626 formula, no virtual shares, no min liquidity lock.
    pub fn deposit(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        let total_supply = Self::total_supply(env.clone());
        let total_assets = Self::total_assets(env.clone());
        let shares: i128 = if total_supply == 0 { amount } else { amount * total_supply / total_assets };
        shares
    }
}
