use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Val, Vec};

#[contract]
pub struct Good;

#[contractimpl]
impl Good {
    // OK: reads the proposal's eta and panics if ledger().timestamp() is
    // before it — enforces the timelock before dispatching.
    pub fn execute_proposal(env: Env, proposal_id: u64, target: Address, fn_name: Symbol, args: Vec<Val>) {
        let key = (Symbol::new(&env, "proposal"), proposal_id);
        let eta: u64 = env.storage().persistent().get(&key).unwrap();
        if env.ledger().timestamp() < eta {
            panic!("timelock");
        }
        let _: Val = env.invoke_contract(&target, &fn_name, args);
    }
}
