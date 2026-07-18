use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: checkpoints accrual BEFORE writing the new rate
    pub fn set_emission_rate(env: Env, asset: Address, new_rate: i128) {
        update_rewards_index(&env, &asset);
        env.storage().persistent().set(&asset, &new_rate);
    }
}

fn update_rewards_index(_: &Env, _: &Address) {}
