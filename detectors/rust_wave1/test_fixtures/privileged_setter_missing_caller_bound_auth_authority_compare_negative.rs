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
    pub fn change_admin(env: Env, authority: Address, new_admin: Address) {
        let cfg = load_config(&env);
        if authority != cfg.admin {
            panic!("only the current admin can rotate admin");
        }
        save_config(&env, &Config { admin: new_admin });
    }
}
