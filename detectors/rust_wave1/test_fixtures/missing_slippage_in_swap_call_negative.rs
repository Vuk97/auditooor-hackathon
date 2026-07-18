use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: swap call with a real min_amount_out.
    pub fn go(env: Env, router: Address, amount_in: i128, min_amount_out: i128, path: Address) {
        let client = RouterClient::new(&env, &router);
        client.swap_exact_in(&amount_in, &min_amount_out, &path);
    }

    // OK: unrelated call — no swap/exchange in name.
    pub fn unrelated(env: Env, a: Address, b: i128) {
        let c = TokenClient::new(&env, &a);
        c.transfer(&b);
    }
}

pub struct RouterClient;
impl RouterClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { RouterClient }
    pub fn swap_exact_in(&self, _a: &i128, _min: &i128, _p: &Address) {}
}
pub struct TokenClient;
impl TokenClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { TokenClient }
    pub fn transfer(&self, _a: &i128) {}
}
