use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Escrow;
#[contractimpl]
impl Escrow {
    // BUG: binary search without handling duplicate-timestamp entries
    pub fn get_past_votes(checkpoints: &[u64], ts: u64) -> u64 {
        let mut lo = 0usize;
        let mut hi = checkpoints.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if checkpoints[mid] <= ts {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        checkpoints.get(lo).copied().unwrap_or(0)
    }
}
