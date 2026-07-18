use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Fractional;
#[contractimpl]
impl Fractional {
    // BUG: divides user_contribution * pool / total_contributed
    // without tracking partial withdraws already made
    pub fn withdraw_contribution(user_contribution: u128, pool: u128) -> u128 {
        user_contribution * pool / total_contributed()
    }
}
fn total_contributed() -> u128 { 1_000_000 }
