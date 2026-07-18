use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        if to == Address::zero() {
            panic!("zero recipient");
        }
        if to == env.current_contract_address() {
            panic!("self recipient");
        }
        token_send(&env, &to, amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        on_behalf_of.require_auth();
        credit_repay(&env, &on_behalf_of, amount);
    }

    pub fn transfer_to(env: Env, recipient: Address, amount: i128) {
        if recipient == Address::zero() {
            panic!("zero recipient");
        }
        token_send(&env, &recipient, amount);
    }

    pub fn repay(env: Env, beneficiary: Address, amount: i128) {
        beneficiary.require_auth();
        credit_repay(&env, &beneficiary, amount);
    }

    pub fn transfer_to(env: Env, recipient: Address, amount: i128) {
        let normalized_recipient = recipient.clone();
        if normalized_recipient == Address::zero() {
            panic!("zero recipient");
        }
        token_send(&env, &normalized_recipient, amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        let checked = on_behalf_of;
        checked.require_auth();
        credit_repay(&env, &checked, amount);
    }

    pub fn withdraw_to(_env: Env, to: Address, amount: i128) -> i128 {
        let _ = to;
        amount
    }

    pub fn transfer_to_allowed(env: Env, recipient: Address, amount: i128) {
        if !allowed_recipients().contains(&recipient) {
            panic!("recipient not allowed");
        }
        token_send(&env, &recipient, amount);
    }
}

fn token_send(_env: &Env, _to: &Address, _amount: i128) {}

fn credit_repay(_env: &Env, _to: &Address, _amount: i128) {}

struct AllowedRecipients;

impl AllowedRecipients {
    fn contains(&self, _recipient: &Address) -> bool {
        true
    }
}

fn allowed_recipients() -> AllowedRecipients {
    AllowedRecipients
}
