use soroban_sdk::{contract, contractimpl};
type Address = [u8; 20];
fn current_liquidity() -> u64 { 10_000 }
fn fee_growth_inside(_tick_lower: i32, _tick_upper: i32) -> u64 { 100 }
fn distribute_to_position(_owner: Address, _amt: u64) {}
fn all_positions() -> Vec<(Address, i32, i32)> { Vec::new() }
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: pays fees proportionally to current in-range liquidity with no cooldown
    pub fn donate(amount: u64) {
        let total = current_liquidity();
        for (owner, lo, hi) in all_positions().iter() {
            let growth = fee_growth_inside(*lo, *hi);
            let share = amount * growth / total;
            distribute_to_position(*owner, share);
        }
    }
}
