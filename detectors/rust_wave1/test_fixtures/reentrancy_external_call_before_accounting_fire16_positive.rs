use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, vec};

pub struct CurvePool;
impl CurvePool {
    pub fn get_virtual_price(&self) -> u128 {
        1_000_000_000_000_000_000
    }
}

#[contract]
pub struct Fire16Vault;

#[contractimpl]
impl Fire16Vault {
    pub fn redeem_before_accounting(env: Env, user: Address, token: Address, shares: i128) {
        user.require_auth();

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

    pub fn withdraw_write_then_call(env: Env, user: Address, token: Address, amount: i128) {
        user.require_auth();
        let next_balance = read_balance(&env, &user) - amount;
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &next_balance);

        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), amount.into_val(&env)],
        );
    }

    pub fn get_price(pool: CurvePool) -> u128 {
        pool.get_virtual_price()
    }
}

enum DataKey {
    Balance(Address),
    Nonce,
}

fn read_balance(_env: &Env, _user: &Address) -> i128 {
    100
}

fn read_nonce(_env: &Env) -> u32 {
    0
}
