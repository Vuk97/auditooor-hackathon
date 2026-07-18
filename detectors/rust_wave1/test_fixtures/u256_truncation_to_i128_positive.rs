use soroban_sdk::{contract, contractimpl, Env, U256};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: silent truncation of a triple-compound product rooted at U256.
    pub fn bad1(env: Env, balance: u128, price: u128, o2w: u128, threshold: u128, dec: u128) -> u128 {
        U256::from_u128(&env, balance)
            .mul(&U256::from_u128(&env, price))
            .mul(&U256::from_u128(&env, o2w))
            .mul(&U256::from_u128(&env, threshold))
            .div(&U256::from_u128(&env, dec))
            .to_u128()
            .unwrap_or(0)
    }

    // VULN: variable named _u256, triple product chain
    pub fn bad2(env: Env, balance_u256: U256, price_u256: U256, o2w_u256: U256, dec_u256: U256) -> u128 {
        balance_u256
            .mul(&price_u256)
            .mul(&o2w_u256)
            .mul(&o2w_u256)
            .div(&dec_u256)
            .to_u128()
            .unwrap()
    }
}
