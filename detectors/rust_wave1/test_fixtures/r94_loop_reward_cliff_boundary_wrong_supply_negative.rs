use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeRewards;
#[contractimpl]
impl SafeRewards {
    // OK: cliff computed from cached pre-mint supply
    pub fn mint(amount: u128) -> u128 {
        let pre_mint_supply = total_supply();
        let cliff = pre_mint_supply / 100_000;
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
