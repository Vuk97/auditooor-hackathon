use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::{contractclient};
    #[contractclient(name = "TokenClient")]
    pub trait Token { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: caller passes `asset`; we build a client and transfer without validating it's listed.
    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128) {
        from.require_auth();
        let client = TokenClient::new(&env, &asset);
        client.transfer(from, env.current_contract_address(), amount);
    }
}
