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
    pub fn change_admin(env: Env, caller: Address, new_admin: Address) {
        if caller == new_admin {
            panic!("self-rotation only");
        }
        let mut cfg = load_config(&env);
        cfg.admin = new_admin;
        save_config(&env, &cfg);
    }
}
