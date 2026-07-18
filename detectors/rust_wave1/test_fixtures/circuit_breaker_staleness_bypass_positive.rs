use soroban_sdk::{contract, contractimpl, Env, Address};

pub struct Reflector;
impl Reflector {
    pub fn new(_env: &Env, _addr: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: &Address) -> Option<u128> { Some(100) }
}

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: consumes Reflector price without a staleness / circuit-breaker check
    pub fn get_asset_price(env: Env, addr: Address, asset: Address) -> u128 {
        let r = Reflector::new(&env, &addr);
        let p = r.lastprice(&asset).unwrap_or(0);
        p
    }

    // VULN: cascades custom oracle + fallback without guard
    pub fn fetch_price_cascade(env: Env, addr: Address, asset: Address) -> u128 {
        let r = Reflector::new(&env, &addr);
        match r.lastprice(&asset) {
            Some(p) => p,
            None => 0,
        }
    }
}
