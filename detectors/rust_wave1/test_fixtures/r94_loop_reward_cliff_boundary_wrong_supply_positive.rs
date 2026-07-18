use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Rewards;
#[contractimpl]
impl Rewards {
    // BUG: cliff computed from post-mint total_supply
    pub fn mint(amount: u128) -> u128 {
        let cliff = total_supply() / 100_000;
        if cliff < total_cliffs() {
            let reduction = total_cliffs() - cliff;
            do_mint(amount);
            return amount * reduction / total_cliffs();
        }
        0
    }
}
fn total_supply() -> u128 { 50_000_000 }
fn total_cliffs() -> u128 { 1000 }
fn do_mint(_a: u128) {}
