use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: mutates state, never re-computes or validates HF after
    pub fn liquidate(env: Env, user: Address, debt_amount: i128, collateral: Address) {
        // check pre-HF
        let _pre = compute_hf(&env, &user);
        // mutate: burn debt tokens
        env.storage().persistent().set(&debt_amount, &0i128);
        // transfer collateral
        let client = TokenClient::new(&env, &collateral);
        client.transfer(env.current_contract_address(), user.clone(), debt_amount);
        // NO post-check
    }
}

fn compute_hf(_: &Env, _: &Address) -> i128 { 0 }

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;
