use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeFractional;
#[contractimpl]
impl SafeFractional {
    // OK: divides by contributions_remaining (tracks withdrawals)
    pub fn withdraw_contribution(user_contribution: u128, pool: u128) -> u128 {
        let remaining = contributions_remaining();
        user_contribution * pool / remaining
    }
}
fn contributions_remaining() -> u128 { 400_000 }
