use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct GoodRewards;

#[contractimpl]
impl GoodRewards {
    pub fn credit_rewards(env: Env, user: Address, amount: i128) {
        env.storage().persistent().set(&Symbol::new(&env, "REWARD_BALANCE"), &user);
        env.storage().instance().update(
            &Symbol::new(&env, "REWARD_COUNT"),
            |n: Option<u32>| n.unwrap_or(0) + 1,
        );
        let _ = amount;
    }

    pub fn claim_rewards(env: Env, user: Address, amount: i128) {
        env.storage().persistent().remove(&Symbol::new(&env, "REWARD_BALANCE"));
        env.storage().instance().set(&Symbol::new(&env, "REWARD_COUNT"), &0u32);
        Self::set_claimed(&env, user.clone(), true);
        token::transfer(&env, user, amount);
    }
}

impl GoodRewards {
    fn set_claimed(_env: &Env, _user: Address, _value: bool) {}
}

mod token {
    pub fn transfer(_env: &super::Env, _user: super::Address, _amount: i128) {}
}
