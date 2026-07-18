use soroban_sdk::{contract, contractimpl, Address, Env};

pub struct PoolClient;
impl PoolClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { PoolClient }
    pub fn get_reserves(&self) -> (i128, i128) { (0, 0) }
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: reads live pool reserves, computes a ratio, uses it as the
    // price to mint shares — no TWAP, no deviation band.
    pub fn mint_from_collateral(env: Env, pool: Address, collateral_amount: i128) -> i128 {
        let p = PoolClient::new(&env, &pool);
        let (r0, r1) = p.get_reserves();
        // spot-price = reserves1 / reserves0, used directly as mint rate
        let price = r1 / r0;
        collateral_amount * price
    }
}
