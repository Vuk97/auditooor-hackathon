use soroban_sdk::{contract, contractimpl};
pub struct Position { pub size: i128 }
#[contract]
pub struct Perp;
#[contractimpl]
impl Perp {
    // BUG: size mutated w/ diff, no position-direction preservation check
    pub fn liquidate(position: &mut Position, size_diff: i128) {
        position.size = position.size + size_diff;
    }
    pub fn deleverage(position: &mut Position, delta_size: i128) {
        position.size += delta_size;
    }
}
