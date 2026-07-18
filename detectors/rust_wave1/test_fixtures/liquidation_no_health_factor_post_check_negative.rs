use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: mutates state AND validates HF post-mutation
    pub fn liquidate(env: Env, user: Address, debt_amount: i128, collateral: Address) {
        let pre_hf = compute_hf(&env, &user);
        env.storage().persistent().set(&debt_amount, &0i128);
        let client = TokenClient::new(&env, &collateral);
        client.transfer(env.current_contract_address(), user.clone(), debt_amount);
        // Post-check
        let post_hf = calculate_health_factor(&env, &user);
        assert!(post_hf > pre_hf);
    }
}

fn compute_hf(_: &Env, _: &Address) -> i128 { 0 }
fn calculate_health_factor(_: &Env, _: &Address) -> i128 { 0 }

mod token {
    use soroban_sdk::contractclient;
    #[contractclient(name = "TokenClient")]
    pub trait T { fn transfer(&self, from: soroban_sdk::Address, to: soroban_sdk::Address, amount: i128); }
}
use token::TokenClient;
