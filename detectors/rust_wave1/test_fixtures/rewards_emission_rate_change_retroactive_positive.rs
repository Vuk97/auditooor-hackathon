use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: writes new rate without checkpoint
    pub fn set_emission_rate(env: Env, asset: Address, new_rate: i128) {
        env.storage().persistent().set(&asset, &new_rate);
    }
}
