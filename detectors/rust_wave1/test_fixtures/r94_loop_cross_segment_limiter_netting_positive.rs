use soroban_sdk::{contract, contractimpl};
pub struct Segment { pub used: u128, pub limit: u128 }
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: per-segment cap only, no global cap
    pub fn borrow(segments: &mut [Segment], segment_id: usize, amount: u128) {
        require(segments[segment_id].used + amount <= segments[segment_id].limit);
        segments[segment_id].used += amount;
    }
}
fn require(_: bool) {}
