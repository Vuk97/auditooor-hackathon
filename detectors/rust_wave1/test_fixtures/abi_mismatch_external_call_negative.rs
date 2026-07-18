use soroban_sdk::{contract, contractimpl, Address, Env};

mod some_other {
    soroban_sdk::contractimport!(file = "target/soroban/other.wasm");
}

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: uses trait-typed client, compiler checks ABI
    pub fn do_call(env: Env, target: Address, amount: i128) {
        let client = some_other::Client::new(&env, &target);
        client.transfer(&amount);
    }
}
