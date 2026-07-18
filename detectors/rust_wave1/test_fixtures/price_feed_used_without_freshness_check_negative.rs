use soroban_sdk::{contract, contractimpl, Address, Env};

struct PriceData { pub price: i128, pub timestamp: u64 }
struct Reflector;
impl Reflector {
    pub fn new(_e: &Env, _a: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: Address) -> Option<PriceData> { None }
}

const MAX_AGE: u64 = 300;

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn value_of(env: Env, oracle: Address, asset: Address, amount: i128) -> i128 {
        let r = Reflector::new(&env, &oracle);
        let p = r.lastprice(asset).unwrap();
        let now = env.ledger().timestamp();
        if now.saturating_sub(p.timestamp) > MAX_AGE { panic!("stale"); }
        amount * p.price
    }
}
