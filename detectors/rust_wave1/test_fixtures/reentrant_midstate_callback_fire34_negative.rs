use soroban_sdk::{contract, contractimpl, vec, Address, Env, Symbol, Val};

#[contract]
pub struct GuardedFire34Escrow;

#[contractimpl]
impl GuardedFire34Escrow {
    pub fn release_after_balance_finalized(
        env: Env,
        user: Address,
        token: Address,
        receiver: Address,
        amount: i128,
    ) {
        user.require_auth();

        let next_balance = read_balance(&env, &user) - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user.clone()), &next_balance);
        env.storage()
            .persistent()
            .set(&DataKey::Settled(user.clone()), &true);

        env.invoke_contract::<()>(
            &receiver,
            &Symbol::new(&env, "on_release"),
            vec![&env, user.into_val(&env), token.into_val(&env)],
        );

        emit_event("release-complete");
    }

    pub fn release_guarded_midstate(
        env: Env,
        user: Address,
        receiver: Address,
        amount: i128,
    ) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PendingWithdrawal(user.clone()), &amount);
        enter_reentrancy_guard();

        env.invoke_contract::<()>(
            &receiver,
            &Symbol::new(&env, "on_release"),
            vec![&env, user.clone().into_val(&env), amount.into_val(&env)],
        );

        env.storage()
            .persistent()
            .set(&DataKey::Settled(user), &true);
    }

    pub fn local_helper_before_finalize(env: Env, user: Address, amount: i128) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PendingWithdrawal(user.clone()), &amount);

        record_local_callback_marker(&user);

        let next_balance = read_balance(&env, &user) - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &next_balance);
    }
}

enum DataKey {
    PendingWithdrawal(Address),
    Balance(Address),
    Settled(Address),
}

fn read_balance(_env: &Env, _user: &Address) -> i128 {
    100
}

fn enter_reentrancy_guard() {}

fn emit_event(_name: &str) {}

fn record_local_callback_marker(_user: &Address) {}
