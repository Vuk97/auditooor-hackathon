use soroban_sdk::{contract, contractimpl};
pub struct Strategy { cap: u64, total_shares: u64 }
pub struct Queue;
fn get_strategy() -> Strategy { Strategy { cap: 0, total_shares: 0 } }
fn save_strategy(_s: &Strategy) {}
#[contract]
pub struct Manager;
#[contractimpl]
impl Manager {
    // BUG: zeros cap but doesn't decrement total_shares / update_withdrawal_queue
    pub fn set_strategy_cap(new_cap: u64) {
        let mut s = get_strategy();
        s.cap = 0;
        save_strategy(&s);
    }
}
