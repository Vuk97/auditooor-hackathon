use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val, vec};

#[contract]
pub struct GuardedVault;

#[contractimpl]
impl GuardedVault {
    pub fn redeem(env: Env, user: Address, token: Address, shares: i128) {
        user.require_auth();
        non_reentrant();

        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), shares.into_val(&env)],
        );

        let next_balance = read_balance(&env, &user) - shares;
        env.storage().persistent().set(&DataKey::Balance(user), &next_balance);
        let next_nonce = read_nonce(&env) + 1;
        env.storage().instance().set(&DataKey::Nonce, &next_nonce);
    }
}

enum DataKey {
    Balance(Address),
    Nonce,
}

fn non_reentrant() {}

fn read_balance(_env: &Env, _user: &Address) -> i128 {
    100
}

fn read_nonce(_env: &Env) -> u32 {
    0
}
