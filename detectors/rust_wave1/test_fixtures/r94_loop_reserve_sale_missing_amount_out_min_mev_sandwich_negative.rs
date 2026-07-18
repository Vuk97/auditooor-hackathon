use soroban_sdk::{contract, contractimpl};

pub struct Router;
impl Router {
    fn swap_with_min(&self, _a: u128, _m: u128) {}
}

#[contract]
pub struct X;

#[contractimpl]
impl X {
    pub fn sell_reserve(amount: u128, min_amount_out: u128) {
        let router = Router;
        router.swap_with_min(amount, min_amount_out);
    }
}
