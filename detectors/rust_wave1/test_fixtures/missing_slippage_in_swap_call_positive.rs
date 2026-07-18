use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN A: swap call with no min_out argument.
    pub fn go(env: Env, router: Address, amount_in: i128, path: Address) {
        let client = RouterClient::new(&env, &router);
        client.swap_exact_in(&amount_in, &path);
    }

    // VULN B: swap call where min_out is literal 0.
    pub fn go2(env: Env, router: Address, amount_in: i128, path: Address) {
        let client = RouterClient::new(&env, &router);
        client.exact_input(&amount_in, &0, &path);
    }
}

// stub
pub struct RouterClient;
impl RouterClient {
    pub fn new(_e: &Env, _a: &Address) -> Self { RouterClient }
    pub fn swap_exact_in(&self, _a: &i128, _p: &Address) {}
    pub fn exact_input(&self, _a: &i128, _min: &i128, _p: &Address) {}
}
