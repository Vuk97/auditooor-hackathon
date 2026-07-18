use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, Vec, IntoVal};

#[contract]
pub struct Bad;

#[contractimpl]
impl Bad {
    // VULN: execute_proposal dispatches the action via invoke_contract
    // immediately after the proposal is loaded — no eta / delay / ready_at
    // check against the ledger timestamp.
    pub fn execute_proposal(env: Env, proposal_id: u64, target: Address, fn_name: Symbol, args: Vec<Val>) {
        let key = (Symbol::new(&env, "proposal"), proposal_id);
        let _stored: u64 = env.storage().persistent().get(&key).unwrap();
        let _: Val = env.invoke_contract(&target, &fn_name, args);
    }
}
