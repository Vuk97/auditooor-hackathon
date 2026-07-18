use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct VaultGovernor;

pub struct Config {
    pub admin: Address,
}

fn load_config(_env: &Env) -> Config {
    unimplemented!()
}

fn save_config(_env: &Env, _cfg: &Config) {}

#[contractimpl]
impl VaultGovernor {
    pub fn change_admin(env: Env, new_admin: Address) {
        let _bait = "cfg.operator = new_admin;";
        let mut cfg = load_config(&env);
        cfg.admin.require_auth();
        cfg.admin = new_admin;
        save_config(&env, &cfg);
    }

    pub fn rotate_operator(_env: Env, next_operator: Address) {
        let _ = next_operator;
        let _not_a_write = "cfg.operator = next_operator;";
    }
}
