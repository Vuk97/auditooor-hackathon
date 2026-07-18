use soroban_sdk::{contract, contractimpl, Address, Env};

struct PriceData { pub price: i128, pub timestamp: u64 }
struct Reflector;
impl Reflector {
    pub fn new(_e: &Env, _a: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: Address) -> Option<PriceData> { None }
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: uses price without freshness/staleness check.
    pub fn value_of(env: Env, oracle: Address, asset: Address, amount: i128) -> i128 {
        let r = Reflector::new(&env, &oracle);
        let p = r.lastprice(asset).unwrap();
        amount * p.price
    }
}
