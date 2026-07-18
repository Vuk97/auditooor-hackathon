use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Loan;
#[contractimpl]
impl Loan {
    // BUG: LTV uses position.size (principal) and excludes accrued interest
    pub fn liquidate(position_amount: u128, position_size: u128) -> bool {
        if position_amount * 1000 / position_size > 900 {
            return false;
        }
        do_liquidate();
        true
    }
}
fn do_liquidate() {}
