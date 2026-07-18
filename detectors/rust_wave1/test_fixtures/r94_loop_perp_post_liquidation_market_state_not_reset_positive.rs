use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Engine;
#[contractimpl]
impl Engine {
    // BUG: clears user position but doesn't decrement open_interest
    pub fn liquidate_position(position_id: u64) {
        positions.remove(&position_id);
    }
}
struct Positions;
impl Positions { fn remove(&self, _p: &u64) {} }
#[allow(non_upper_case_globals)]
static positions: Positions = Positions;
