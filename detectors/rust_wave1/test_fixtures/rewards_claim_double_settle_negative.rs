use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn claim_rewards(env: Env, user: Address, reserve: Address) -> i128 {
        user.require_auth();
        let key = (Symbol::new(&env, "accrued"), user.clone(), reserve.clone());
        let amt: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &0i128);
        amt
    }

    // Good: delegates to claim_rewards per reserve.
    pub fn claim_all(env: Env, user: Address, reserves: Vec<Address>) -> i128 {
        user.require_auth();
        let mut total: i128 = 0;
        for r in reserves.iter() {
            total += Self::claim_rewards(env.clone(), user.clone(), r.clone());
        }
        total
    }
}
