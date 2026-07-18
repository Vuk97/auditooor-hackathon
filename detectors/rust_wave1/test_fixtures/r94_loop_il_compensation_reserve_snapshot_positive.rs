use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: il_compensation from current reserves, no TWAP
    pub fn burn(shares: u128, reserve_a: u128, reserve_b: u128) -> u128 {
        let impermanent_loss = compute_il(reserve_a, reserve_b);
        shares + impermanent_loss
    }
}
fn compute_il(_a: u128, _b: u128) -> u128 { 0 }
