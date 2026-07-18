use soroban_sdk::{contract, contractimpl, Env, Address};

pub struct Reflector;
impl Reflector {
    pub fn new(_env: &Env, _addr: &Address) -> Self { Reflector }
    pub fn lastprice(&self, _asset: &Address) -> Option<u128> { Some(100) }
}

fn validate_price_staleness(_env: &Env, _price: u128) -> Result<(), ()> { Ok(()) }
fn validate_price_change(_env: &Env, _price: u128) -> Result<(), ()> { Ok(()) }

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    pub fn get_asset_price(env: Env, addr: Address, asset: Address) -> u128 {
        let r = Reflector::new(&env, &addr);
        let p = r.lastprice(&asset).unwrap_or(0);
        validate_price_staleness(&env, p).ok();
        validate_price_change(&env, p).ok();
        p
    }
}
