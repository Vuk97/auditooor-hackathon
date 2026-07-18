use soroban_sdk::{contract, contractimpl};
pub struct Lock { amount: u64, end_time: u64 }
fn load_locks() -> Vec<Lock> { Vec::new() }
fn now() -> u64 { 0 }
#[contract]
pub struct VeRaacToken;
#[contractimpl]
impl VeRaacToken {
    // SAFE: sums locked-weight voting power across all active locks
    pub fn get_total_voting_power() -> u64 {
        let locks = load_locks();
        let mut sum_over_locks: u64 = 0;
        let t = now();
        for l in locks.iter() {
            if l.end_time > t {
                sum_over_locks += l.amount * (l.end_time - t);
            }
        }
        sum_over_locks
    }
}
