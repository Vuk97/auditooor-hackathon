use soroban_sdk::{contract, contractimpl, contracttype, Env, Address};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Config,
    Initialized,
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN 1: per-user Balance on instance() storage (capacity cap)
    pub fn set_balance(env: Env, who: Address, amount: i128) {
        env.storage().instance().set(&DataKey::Balance(who), &amount);
    }

    // VULN 2: tier confusion — write persistent, read instance
    pub fn mixed_tier(env: Env, who: Address) -> i128 {
        env.storage().persistent().set(&DataKey::Balance(who.clone()), &42i128);
        env.storage().instance().get(&DataKey::Balance(who)).unwrap_or(0)
    }

    // VULN 3: singleton Config on persistent() (wastes TTL)
    pub fn set_config(env: Env, cfg: i128) {
        env.storage().persistent().set(&DataKey::Config, &cfg);
    }
}
