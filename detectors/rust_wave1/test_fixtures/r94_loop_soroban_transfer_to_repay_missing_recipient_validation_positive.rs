use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        transfer_to(&env, &to, &amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        repay(&env, &on_behalf_of, &amount);
    }
}

fn transfer_to(_env: &Env, _to: &Address, _amount: &i128) {}

fn repay(_env: &Env, _on_behalf_of: &Address, _amount: &i128) {}
