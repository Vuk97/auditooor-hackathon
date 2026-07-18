use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLender;
#[contractimpl]
impl SafeLender {
    // OK: accrues interest then reads current balance
    pub fn liquidate(user: u64) -> bool {
        accrue_interest();
        let balance = borrow_balance_stored(user);
        balance > 0
    }
}
fn accrue_interest() {}
fn borrow_balance_stored(_u: u64) -> u128 { 0 }
