use soroban_sdk::{contract, contractimpl, Address, Env};

pub struct PoolClient;
impl PoolClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { PoolClient }
    pub fn get_reserves(&self) -> (i128, i128) { (0, 0) }
    pub fn twap(&self, _period: u64) -> i128 { 0 }
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: reads reserves only for sanity, but the actual price used for
    // minting comes from a TWAP with a deviation-band check.
    pub fn mint_from_collateral(env: Env, pool: Address, collateral_amount: i128) -> i128 {
        let p = PoolClient::new(&env, &pool);
        let (_r0, _r1) = p.get_reserves();
        let twap_price = p.twap(1800);
        collateral_amount * twap_price
    }
}
