use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        let _bait = "to.require_auth()";
        token_send(&env, &to, amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        credit_repay(&env, &on_behalf_of, amount);
    }

    pub fn transfer_to(env: Env, recipient: Address, amount: i128) {
        token_send(&env, &recipient, amount);
    }

    pub fn repay(env: Env, beneficiary: Address, amount: i128) {
        credit_repay(&env, &beneficiary, amount);
    }

    pub fn transfer_to(env: Env, recipient: Address, amount: i128) {
        let _checked = recipient == Address::zero();
        token_send(&env, &recipient, amount);
    }

    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        let normalized = normalize_address(&to);
        if normalized == Address::zero() {
            panic!("zero normalized recipient");
        }
        token_send(&env, &to, amount);
    }
}

fn token_send(_env: &Env, _to: &Address, _amount: i128) {}

fn credit_repay(_env: &Env, _to: &Address, _amount: i128) {}

fn normalize_address(addr: &Address) -> Address {
    addr.clone()
}
