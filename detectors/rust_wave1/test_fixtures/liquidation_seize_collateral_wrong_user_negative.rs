use soroban_sdk::{contract, contractimpl, Address, Env};

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T {
        fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128);
        fn transfer_from(&self, spender: soroban_sdk::Address, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128);
    }
}
use token::TokenClient;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: collateral pulled from borrower, not liquidator
    pub fn liquidate(env: Env, liquidator: Address, borrower: Address, collateral: Address, amount: i128) {
        let c_token = TokenClient::new(&env, &collateral);
        c_token.transfer_from(liquidator.clone(), borrower.clone(), liquidator.clone(), amount);
    }
}
