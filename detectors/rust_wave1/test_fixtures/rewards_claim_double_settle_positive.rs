use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    pub fn claim_rewards(env: Env, user: Address, reserve: Address) -> i128 {
        user.require_auth();
        let key = (Symbol::new(&env, "accrued"), user.clone(), reserve.clone());
        let amt: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &0i128);
        amt
    }

    // VULN: claim_all transfers but doesn't reset the accrual keys or call claim_rewards.
    pub fn claim_all(env: Env, user: Address, reserves: Vec<Address>) -> i128 {
        user.require_auth();
        let mut total: i128 = 0;
        for r in reserves.iter() {
            let key = (Symbol::new(&env, "accrued"), user.clone(), r.clone());
            let amt: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            total += amt;
        }
        total
    }
}
