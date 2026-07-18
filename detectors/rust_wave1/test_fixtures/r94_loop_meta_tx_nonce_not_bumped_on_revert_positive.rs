use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Meta;
#[contractimpl]
impl Meta {
    // BUG: inner call reverts → whole tx reverts, nonce stays
    pub fn execute_meta_tx(from: u64, data: u128, sig: u128) {
        let _ = sig;
        env.invoke_contract(from, data);
    }
}
struct Env;
impl Env { fn invoke_contract(&self, _t: u64, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env;
