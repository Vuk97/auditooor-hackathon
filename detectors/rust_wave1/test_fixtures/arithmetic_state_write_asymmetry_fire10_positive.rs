use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct RewardVault;

#[contractimpl]
impl RewardVault {
    pub fn credit_rewards(env: Env, user: Address, amount: i128) {
        let key = (Symbol::new(&env, "REWARDS"), user);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let next = current + amount;
        env.storage().persistent().set(&key, &next);
    }

    // BUG: claim_rewards pays from the same credited bucket but never clears it.
    pub fn claim_rewards(env: Env, user: Address) {
        let key = (Symbol::new(&env, "REWARDS"), user.clone());
        let amount: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        token::transfer(&env, user, amount);
    }
}

mod token {
    use soroban_sdk::{Address, Env};

    pub fn transfer(_env: &Env, _to: Address, _amount: i128) {}
}
