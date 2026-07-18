use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeWrapper;
#[contractimpl]
impl SafeWrapper {
    // OK: shares sized on actual balance-diff received, not pre-fee amount
    pub fn deposit(amount: u128) -> u128 {
        let balance_before = balance_of(vault());
        underlying.deposit(amount);
        let received = balance_of(vault()) - balance_before;
        let shares = preview_deposit(received);
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
