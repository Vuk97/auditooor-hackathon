use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Prize;
#[contractimpl]
impl Prize {
    // BUG: divides by total_supply, not eligible_supply
    pub fn claim_prize(user_balance: u128, prize_amount: u128) -> u128 {
        let share = prize_amount * user_balance / total_supply();
        share
    }
}
fn total_supply() -> u128 { 1_000_000 }
