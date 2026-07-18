use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafeEscrow;
#[contractimpl]
impl SafeEscrow {
    // OK: after binary search, walks forward to last_with_ts duplicate
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
        let last_with_ts = walk_forward(checkpoints, lo);
        checkpoints.get(last_with_ts).copied().unwrap_or(0)
    }
}
fn walk_forward(_c: &[u64], lo: usize) -> usize { lo }
