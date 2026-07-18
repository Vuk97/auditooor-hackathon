use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeBridge;
#[contractimpl]
impl SafeBridge {
    // OK: checks is_approved(target) before invoke
    pub fn swap_and_bridge(target: u64, calldata: u128) -> u128 {
        if !is_approved(target) { panic!("target not allowlisted"); }
        env.invoke_contract(target, calldata);
        0
    }
}
fn is_approved(_t: u64) -> bool { true }
struct Env { }
impl Env { fn invoke_contract(&self, _t: u64, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
