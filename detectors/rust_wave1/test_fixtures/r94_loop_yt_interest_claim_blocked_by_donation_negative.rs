use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeYT;
#[contractimpl]
impl SafeYT {
    // OK: reconciles donated reserves before computing interest diff
    pub fn claim_interest(user: u64) -> u128 {
        reconcile_reserves();
        let total = total_interest();
        let claimed = already_claimed(user);
        total.checked_sub(claimed).unwrap()
    }
}
fn reconcile_reserves() {}
fn total_interest() -> u128 { 0 }
fn already_claimed(_u: u64) -> u128 { 0 }
