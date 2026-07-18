use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: unwrap() in pub fn inside #[contractimpl]
    pub fn read(env: Env, who: Address) -> i128 {
        let v: Option<i128> = env.storage().persistent().get(&who);
        v.unwrap()
    }

    pub fn read2(env: Env, who: Address) -> i128 {
        env.storage().persistent().get::<_, i128>(&who).expect("missing")
    }
}
