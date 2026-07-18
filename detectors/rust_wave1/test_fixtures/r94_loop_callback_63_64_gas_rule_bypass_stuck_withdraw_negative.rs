use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePortal;
#[contractimpl]
impl SafePortal {
    // OK: reserves MIN_FINALIZE_GAS for post-call resumption
    pub fn finalize_withdrawal(target: u64, gas_limit: u64, data: &[u8]) -> bool {
        let _ = data;
        require_gas_left(MIN_FINALIZE_GAS);
        env.invoke_contract_with_gas(target, gas_limit);
        true
    }
}
fn require_gas_left(_g: u64) {}
const MIN_FINALIZE_GAS: u64 = 100_000;
struct Env;
impl Env { fn invoke_contract_with_gas(&self, _t: u64, _g: u64) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env;
