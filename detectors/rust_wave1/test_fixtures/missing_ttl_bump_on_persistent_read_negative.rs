use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn read_and_act(env: Env, who: Address) -> i128 {
        let v: i128 = env.storage().persistent().get(&who).unwrap_or(1);
        env.storage().persistent().extend_ttl(&who, 100, 200);
        v + 1
    }
}
