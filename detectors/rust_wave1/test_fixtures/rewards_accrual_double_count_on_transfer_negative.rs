use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // SAFE: early-exits on self-transfer before double-counting
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if from == to {
            return;
        }
        handle_action(&env, &from, amount);
        handle_action(&env, &to, amount);
    }
}

fn handle_action(_: &Env, _: &Address, _: i128) {}
