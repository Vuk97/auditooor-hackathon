use soroban_sdk::{contract, contractimpl};

pub struct Router;
impl Router {
    fn swap(&self, _a: u128) -> u128 { 0 }
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn sell_reserve(amount: u128) {
        let router = Router;
        let sold = router.swap(amount);
        let _ = sold;
    }
}
