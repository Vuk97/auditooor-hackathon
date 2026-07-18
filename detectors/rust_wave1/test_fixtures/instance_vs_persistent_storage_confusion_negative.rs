use soroban_sdk::{contract, contractimpl, contracttype, Env, Address};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Config,
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: per-user Balance on persistent() storage
    pub fn set_balance(env: Env, who: Address, amount: i128) {
        env.storage().persistent().set(&DataKey::Balance(who), &amount);
    }

    pub fn get_balance(env: Env, who: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(who)).unwrap_or(0)
    }

    // OK: singleton Config on instance() storage
    pub fn set_config(env: Env, cfg: i128) {
        env.storage().instance().set(&DataKey::Config, &cfg);
    }

    pub fn get_config(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Config).unwrap_or(0)
    }
}
