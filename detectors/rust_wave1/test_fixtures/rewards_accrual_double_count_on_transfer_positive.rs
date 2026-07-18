use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: calls handle_action for from AND to without self-transfer guard
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        handle_action(&env, &from, amount);
        handle_action(&env, &to, amount);
        let balance = 0i128;
        env.storage().persistent().set(&from, &balance);
    }
}

fn handle_action(_: &Env, _: &Address, _: i128) {}
