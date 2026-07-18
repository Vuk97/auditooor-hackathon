use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lender;
#[contractimpl]
impl Lender {
    // BUG: reads borrow_balance_stored without accruing interest first
    pub fn liquidate(user: u64) -> bool {
        let balance = borrow_balance_stored(user);
        balance > 0
    }
}
fn borrow_balance_stored(_u: u64) -> u128 { 0 }
