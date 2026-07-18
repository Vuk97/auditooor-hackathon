use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEngine;
#[contractimpl]
impl SafeEngine {
    // OK: decrements open_interest and position_count on liquidation
    pub fn liquidate_position(position_id: u64) {
        let mut open_interest = 0u128;
        open_interest -= 1;
        let _ = open_interest;
        let mut position_count = 0u128;
        position_count -= 1;
        positions.remove(&position_id);
    }
}
struct Positions;
impl Positions { fn remove(&self, _p: &u64) {} }
#[allow(non_upper_case_globals)]
static positions: Positions = Positions;
