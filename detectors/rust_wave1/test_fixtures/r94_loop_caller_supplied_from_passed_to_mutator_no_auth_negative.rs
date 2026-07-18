use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

fn spend_allowance(_env: &Env, _from: &Address, _amount: i128) {}
fn set_delegate(_env: &Env, _from: &Address, _delegate: &Address) {}

#[contractimpl]
impl Good {
    pub fn delegate_for(env: Env, from: Address, delegate: Address) {
        from.require_auth();
        spend_allowance(&env, &from, 10);
        set_delegate(&env, &from, &delegate);
    }
}
