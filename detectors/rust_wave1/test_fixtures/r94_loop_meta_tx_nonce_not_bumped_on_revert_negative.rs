use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeMeta;
#[contractimpl]
impl SafeMeta {
    // OK: bump nonce BEFORE the inner call (even if reverts, nonce committed)
    pub fn execute_meta_tx(from: u64, data: u128, sig: u128) {
        let _ = sig;
        nonces[from] += 1;
        env.invoke_contract(from, data);
    }
}
struct Env;
impl Env { fn invoke_contract(&self, _t: u64, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env;
#[allow(non_upper_case_globals)]
static mut nonces: [u64; 16] = [0u64; 16];
