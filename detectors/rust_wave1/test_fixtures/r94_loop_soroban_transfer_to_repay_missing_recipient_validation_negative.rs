use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        if to == Address::zero() {
            panic!("bad recipient");
        }
        if to == env.current_contract_address() {
            panic!("self recipient");
        }
        if !is_whitelisted(&to) {
            panic!("recipient not allowed");
        }
        transfer_to(&env, &to, &amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        on_behalf_of.require_auth();
        repay(&env, &on_behalf_of, &amount);
    }
}

fn transfer_to(_env: &Env, _to: &Address, _amount: &i128) {}

fn repay(_env: &Env, _on_behalf_of: &Address, _amount: &i128) {}

fn is_whitelisted(_to: &Address) -> bool {
    true
}
