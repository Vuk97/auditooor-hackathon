use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

fn spend_allowance(_env: &Env, _from: &Address, _amount: i128) {}
fn set_delegate(_env: &Env, _from: &Address, _delegate: &Address) {}

#[contractimpl]
impl Bad {
    pub fn delegate_for(env: Env, from: Address, delegate: Address) {
        spend_allowance(&env, &from, 10);
        set_delegate(&env, &from, &delegate);
    }
}
