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

fn assert_admin(env: &Env, admin: &Address) {
    let _ = env;
    admin.require_auth();
}

#[contractimpl]
impl VaultGovernor {
    pub fn change_admin(env: Env, new_admin: Address) {
        let mut cfg = load_config(&env);
        assert_admin(&env, &cfg.admin);
        cfg.admin = new_admin;
        save_config(&env, &cfg);
    }
}
