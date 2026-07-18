use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Portal;
#[contractimpl]
impl Portal {
    // BUG: forwards caller gas_limit without reserving stipend
    pub fn finalize_withdrawal(target: u64, gas_limit: u64, data: &[u8]) -> bool {
        let _ = data;
        env.invoke_contract_with_gas(target, gas_limit);
        true
    }
}
struct Env;
impl Env { fn invoke_contract_with_gas(&self, _t: u64, _g: u64) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env;
