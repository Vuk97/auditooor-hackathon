use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Timelock;
#[contractimpl]
impl Timelock {
    // BUG: forwards value but never refunds leftover
    pub fn execute_transaction(target: u64, value: u128, data: u128) -> u128 {
        env.invoke_contract(target, value, data);
        0
    }
}
struct Env { }
impl Env { fn invoke_contract(&self, _t: u64, _v: u128, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
