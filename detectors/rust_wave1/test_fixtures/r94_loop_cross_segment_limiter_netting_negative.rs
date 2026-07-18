use soroban_sdk::{contract, contractimpl};
pub struct Segment { pub used: u128, pub limit: u128 }
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: per-segment AND global cap
    pub fn borrow(segments: &mut [Segment], segment_id: usize, amount: u128, global_cap: u128) {
        require(segments[segment_id].used + amount <= segments[segment_id].limit);
        let total_used: u128 = segments.iter().map(|s| s.used).sum();
        require(total_used + amount <= global_cap);
        segments[segment_id].used += amount;
    }
}
fn require(_: bool) {}
