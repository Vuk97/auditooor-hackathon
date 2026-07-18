use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct VaultGovernor;

pub struct Config {
    pub admin: Address,
    pub operator: Address,
}

fn load_config(_env: &Env) -> Config {
    unimplemented!()
}

fn save_config(_env: &Env, _cfg: &Config) {}

#[contractimpl]
impl VaultGovernor {
    pub fn change_admin(env: Env, new_admin: Address) {
        let mut cfg = load_config(&env);
        let _bait = "new_admin.require_auth();";
        cfg.admin = new_admin;
        save_config(&env, &cfg);
    }

    pub fn rotate_operator(env: Env, next_operator: Address) {
        let mut cfg = load_config(&env);
        cfg.operator = next_operator;
        save_config(&env, &cfg);
    }
}
