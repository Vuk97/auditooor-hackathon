use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

mod token {
    use soroban_sdk::{contractclient};
    #[contractclient(name = "TokenClient")]
    pub trait Token { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    fn assert_allowed_token(env: &Env, a: &Address) {
        let _ok: bool = env.storage().persistent().get(&(Symbol::new(env, "lst"), a.clone())).unwrap_or(false);
    }
    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128) {
        from.require_auth();
        Self::assert_allowed_token(&env, &asset);
        let client = TokenClient::new(&env, &asset);
        client.transfer(from, env.current_contract_address(), amount);
    }
}
