use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: public mint() credits shares to any caller-supplied address
    // with no require_auth and no supply-cap check — unlimited mint.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = (Symbol::new(&env, "Balance"), to);
        let prev: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(prev + amount));
    }
}
