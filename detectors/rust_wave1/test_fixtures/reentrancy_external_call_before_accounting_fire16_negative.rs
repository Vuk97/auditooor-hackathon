use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, vec};

pub struct CurvePool;
impl CurvePool {
    pub fn get_virtual_price(&self) -> u128 {
        1_000_000_000_000_000_000
    }

    pub fn remove_liquidity(&self, _amount: u128, _mins: [u128; 2]) {}
}

#[contract]
pub struct GuardedFire16Vault;

#[contractimpl]
impl GuardedFire16Vault {
    pub fn redeem_guarded(env: Env, user: Address, token: Address, shares: i128) {
        user.require_auth();
        non_reentrant();

        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), shares.into_val(&env)],
        );

        let next_balance = read_balance(&env, &user) - shares;
        env.storage().persistent().set(&DataKey::Balance(user), &next_balance);
    }

    pub fn withdraw_guarded(env: Env, user: Address, token: Address, amount: i128) {
        user.require_auth();
        enter_reentrancy_guard();
        let next_balance = read_balance(&env, &user) - amount;
        env.storage().persistent().set(&DataKey::Balance(user.clone()), &next_balance);

        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "transfer"),
            vec![&env, user.into_val(&env), amount.into_val(&env)],
        );
    }

    pub fn get_price(pool: CurvePool) -> u128 {
        pool.remove_liquidity(0, [0, 0]);
        pool.get_virtual_price()
    }
}

enum DataKey {
    Balance(Address),
}

fn non_reentrant() {}

fn enter_reentrancy_guard() {}

fn read_balance(_env: &Env, _user: &Address) -> i128 {
    100
}
