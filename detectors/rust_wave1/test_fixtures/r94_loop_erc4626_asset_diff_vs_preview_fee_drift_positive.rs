use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Wrapper;
#[contractimpl]
impl Wrapper {
    // BUG: measures balance-diff but sizes shares via preview_deposit(amount)
    pub fn deposit(amount: u128) -> u128 {
        let balance_before = balance_of(vault());
        underlying.deposit(amount);
        let received = balance_of(vault()) - balance_before;
        let _ = received;
        let shares = preview_deposit(amount);
        shares
    }
}
fn balance_of(_v: u64) -> u128 { 0 }
fn vault() -> u64 { 0 }
fn preview_deposit(_a: u128) -> u128 { 0 }
struct Underlying;
impl Underlying { fn deposit(&self, _a: u128) {} }
#[allow(non_upper_case_globals)]
static underlying: Underlying = Underlying;
