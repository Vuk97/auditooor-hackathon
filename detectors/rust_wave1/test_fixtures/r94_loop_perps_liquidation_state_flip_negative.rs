use soroban_sdk::{contract, contractimpl};
pub struct Position { pub size: i128 }
#[contract]
pub struct SafePerp;
#[contractimpl]
impl SafePerp {
    // OK: direction preserved check
    pub fn liquidate(position: &mut Position, size_diff: i128) {
        let was_long = position.size > 0;
        position.size = position.size + size_diff;
        let is_long_after = position.size > 0;
        require(was_long == is_long_after || position.size == 0);
    }
    pub fn deleverage(position: &mut Position, delta_size: i128) {
        position.size += delta_size;
        assert_direction(position);
    }
}
fn assert_direction(_p: &Position) {}
fn require(_: bool) {}
