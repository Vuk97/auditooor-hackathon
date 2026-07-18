use soroban_sdk::{contract, contractimpl};
fn total_supply() -> u64 { 1_000_000 }
#[contract]
pub struct VeRaacToken;
#[contractimpl]
impl VeRaacToken {
    // BUG: returns total_supply() directly as voting power
    pub fn get_total_voting_power() -> u64 {
        return total_supply();
    }
}
