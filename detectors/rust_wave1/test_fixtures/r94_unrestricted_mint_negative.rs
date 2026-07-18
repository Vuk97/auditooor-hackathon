use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: loads the minter role, calls require_auth on it, and enforces
    // a supply cap.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let mkey = Symbol::new(&env, "Minter");
        let minter: Address = env.storage().instance().get(&mkey).unwrap();
        minter.require_auth();
        let skey = Symbol::new(&env, "TotalSupply");
        let prev_supply: i128 = env.storage().instance().get(&skey).unwrap_or(0);
        let max_supply: i128 = 1_000_000_000;
        if prev_supply + amount > max_supply {
            panic!("cap");
        }
        env.storage().instance().set(&skey, &(prev_supply + amount));
        let bkey = (Symbol::new(&env, "Balance"), to);
        let prev: i128 = env.storage().persistent().get(&bkey).unwrap_or(0);
        env.storage().persistent().set(&bkey, &(prev + amount));
    }
}
