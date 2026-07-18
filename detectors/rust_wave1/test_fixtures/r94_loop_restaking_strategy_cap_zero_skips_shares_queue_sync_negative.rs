use soroban_sdk::{contract, contractimpl};
pub struct Strategy { cap: u64, total_shares: u64 }
pub struct Queue;
fn get_strategy() -> Strategy { Strategy { cap: 0, total_shares: 0 } }
fn save_strategy(_s: &Strategy) {}
fn update_total_shares(_s: &mut Strategy) {}
fn update_withdrawal_queue() {}
#[contract]
pub struct Manager;
#[contractimpl]
impl Manager {
    // SAFE: zeros cap and also calls update_total_shares + update_withdrawal_queue
    pub fn set_strategy_cap(new_cap: u64) {
        let mut s = get_strategy();
        s.cap = 0;
        update_total_shares(&mut s);
        update_withdrawal_queue();
        save_strategy(&s);
    }
}
