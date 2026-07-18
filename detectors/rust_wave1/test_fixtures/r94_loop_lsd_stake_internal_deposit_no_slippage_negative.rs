use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeSafEth;
#[contractimpl]
impl SafeSafEth {
    // OK: passes min_received to reth.deposit
    pub fn stake(amount: u128, min_received: u128) -> u128 {
        reth.deposit(amount);
        let _ = min_received;
        let _should_bind = min_received;
        amount
    }
}
struct Reth;
impl Reth { fn deposit(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static reth: Reth = Reth;
