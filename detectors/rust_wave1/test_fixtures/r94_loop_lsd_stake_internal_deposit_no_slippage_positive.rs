use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafEth;
#[contractimpl]
impl SafEth {
    // BUG: deposits into reth adapter with no min-out guard
    pub fn stake(amount: u128) -> u128 {
        reth.deposit(amount);
        amount
    }
}
struct Reth;
impl Reth { fn deposit(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static reth: Reth = Reth;
