use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeTimelock;
#[contractimpl]
impl SafeTimelock {
    // OK: refund_caller for leftover value
    pub fn execute_transaction(target: u64, value: u128, data: u128, proposer: u64) -> u128 {
        let balance_before = balance();
        env.invoke_contract(target, value, data);
        let leftover = balance() - balance_before;
        refund_caller(proposer, leftover);
        0
    }
}
fn balance() -> u128 { 0 }
fn refund_caller(_p: u64, _a: u128) {}
struct Env { }
impl Env { fn invoke_contract(&self, _t: u64, _v: u128, _d: u128) {} }
#[allow(non_upper_case_globals)]
static env: Env = Env{};
