use soroban_sdk::{contract, contractimpl};
pub struct Position { pub size: i128, pub collateral: i128 }
#[contract]
pub struct Perp;
#[contractimpl]
impl Perp {
    // BUG: size is mutated BEFORE the solvency check that references size
    pub fn execute_transfer(pos: &mut Position, diff: i128) {
        pos.size = pos.size + diff;
        require(pos.size >= 0);
    }
}
fn require(_c: bool) {}
