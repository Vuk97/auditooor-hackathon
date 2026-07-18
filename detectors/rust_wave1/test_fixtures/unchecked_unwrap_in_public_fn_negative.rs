use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn read(env: Env, who: Address) -> i128 {
        let v: Option<i128> = env.storage().persistent().get(&who);
        v.unwrap_or(0i128)
    }

    pub fn read2(env: Env, who: Address) -> i128 {
        env.storage()
            .persistent()
            .get::<_, i128>(&who)
            .unwrap_or_else(|| panic!("missing"))
    }
}
