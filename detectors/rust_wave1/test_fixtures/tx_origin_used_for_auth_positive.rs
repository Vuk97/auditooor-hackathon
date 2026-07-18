use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: caller auths, but funds come from `victim`.
    pub fn move_funds(env: Env, caller: Address, victim: Address, asset: Address, amount: i128) {
        caller.require_auth();
        let client = TokenClient::new(&env, &asset);
        client.transfer(victim, caller, amount);
    }
}
