use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Lend;
#[contractimpl]
impl Lend {
    // BUG: increments borrow_amount without accruing interest first
    pub fn handle_borrow(user: u64, amount: u128) {
        borrow_amount[user] += amount;
    }
}
#[allow(non_upper_case_globals)]
static mut borrow_amount: [u128; 2] = [0, 0];
