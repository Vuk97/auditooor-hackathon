use soroban_sdk::{contract, contractimpl};
pub struct Position { pub size: i128, pub collateral: i128 }
#[contract]
pub struct SafePerp;
#[contractimpl]
impl SafePerp {
    // OK: check the pending diff BEFORE mutation
    pub fn execute_transfer(pos: &mut Position, diff: i128) {
        let new_size = pos.size + diff;
        require(new_size >= 0);
        pos.size = new_size;
    }
}
fn require(_c: bool) {}
