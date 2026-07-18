use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeLend;
#[contractimpl]
impl SafeLend {
    // OK: accrue_interest(user) called before updating principal
    pub fn handle_borrow(user: u64, amount: u128) {
        accrue_interest(user);
        borrow_amount[user] += amount;
    }
}
fn accrue_interest(_u: u64) {}
#[allow(non_upper_case_globals)]
static mut borrow_amount: [u128; 2] = [0, 0];
