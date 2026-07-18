use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: reads persistent storage, never extends TTL
    pub fn read_and_act(env: Env, who: Address) -> i128 {
        let v: i128 = env.storage().persistent().get(&who).unwrap_or(1);
        v + 1
    }
}
