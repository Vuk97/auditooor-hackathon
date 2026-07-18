use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePrize;
#[contractimpl]
impl SafePrize {
    // OK: divides by eligible_supply (only participants)
    pub fn claim_prize(user_balance: u128, prize_amount: u128) -> u128 {
        let share = prize_amount * user_balance / eligible_supply();
        share
    }
}
fn eligible_supply() -> u128 { 500_000 }
