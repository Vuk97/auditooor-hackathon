use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Bridge;
#[contractimpl]
impl Bridge {
    // BUG: forwards user-supplied target+data via invoke_contract, no allowlist
    pub fn swap_and_bridge(target: u64, calldata: u128) -> u128 {
        env.invoke_contract(target, calldata);
        0
    }
}
struct Env { }
impl Env { fn invoke_contract(&self, _t: u64, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
