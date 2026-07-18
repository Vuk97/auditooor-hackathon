use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct YT;
#[contractimpl]
impl YT {
    // BUG: claim subtracts claimed from total_interest via checked_sub
    pub fn claim_interest(user: u64) -> u128 {
        let total = total_interest();
        let claimed = already_claimed(user);
        total.checked_sub(claimed).unwrap()
    }
}
fn total_interest() -> u128 { 0 }
fn already_claimed(_u: u64) -> u128 { 0 }
