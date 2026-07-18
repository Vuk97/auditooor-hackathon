use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn withdraw_to(env: Env, to: Address, amount: i128) {
        let reject_zero = to == Address::zero();
        if reject_zero {
            panic!("zero recipient");
        }
        token_send(&env, &to, amount);
    }

    pub fn repay_for(env: Env, on_behalf_of: Address, amount: i128) {
        let deny_self = on_behalf_of == env.current_contract_address();
        if deny_self {
            panic!("self recipient");
        }
        credit_repay(&env, &on_behalf_of, amount);
    }

    pub fn transfer_to(env: Env, recipient: Address, amount: i128) {
        let allowed = allowed_recipients().contains(&recipient);
        if !allowed {
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
