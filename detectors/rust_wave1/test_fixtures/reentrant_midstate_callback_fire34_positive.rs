use soroban_sdk::{contract, contractimpl, vec, Address, Env, Symbol, Val};

#[contract]
pub struct Fire34Escrow;

#[contractimpl]
impl Fire34Escrow {
    pub fn release_with_midstate_callback(
        env: Env,
        user: Address,
        token: Address,
        receiver: Address,
        amount: i128,
    ) {
        user.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::PendingWithdrawal(user.clone()), &amount);

        env.invoke_contract::<()>(
            &receiver,
            &Symbol::new(&env, "on_release"),
            vec![&env, user.clone().into_val(&env), token.into_val(&env)],
        );

        let next_balance = read_balance(&env, &user) - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user.clone()), &next_balance);
        env.storage()
            .persistent()
            .set(&DataKey::Settled(user), &true);
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
