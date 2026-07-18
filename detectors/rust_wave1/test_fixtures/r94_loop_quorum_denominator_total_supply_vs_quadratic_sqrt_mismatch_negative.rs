use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn total_supply() -> u128 { 1_000_000_000_000_000_000_u128 }
fn sqrt_total_supply() -> u128 { 1_000_000_000_u128 }
fn balance_of(_who: Address) -> u128 { 1_000_000_000_000_u128 }
fn isqrt(x: u128) -> u128 { let mut r = x; let mut i = 0u128; while i * i <= x { i += 1; r = i; } r }
#[contract]
pub struct QuadraticGovernor;
#[contractimpl]
impl QuadraticGovernor {
    // SAFE: sqrt vote weight and quorum denominator also sqrt-scaled
    pub fn _quorum_reached(for_votes_sqrt: u128) -> bool {
        let weight = isqrt(balance_of([0; 20]));
        let _used = weight;
        let _sup = total_supply();
        let sqrt_sup = sqrt_total_supply();
        for_votes_sqrt * 100 >= sqrt_sup * 25
    }
}
