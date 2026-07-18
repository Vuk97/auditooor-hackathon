use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec, Val};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: target AND (symbol, args) come from caller → arbitrary call
    pub fn forward(env: Env, target: Address, method: Symbol, args: Vec<Val>) {
        let _r: Val = env.invoke_contract(&target, &method, args);
    }
}
