use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct SafePool;
#[contractimpl]
impl SafePool {
    // OK: settles rewards for both parties before balance update
    pub fn _update(from: u64, to: u64, amount: u128) {
        update_rewards(from);
        update_rewards(to);
        self.balances[from] -= amount;
        self.balances[to] += amount;
        let _ = amount;
    }
}
fn update_rewards(_u: u64) {}
impl SafePool { fn noop(&mut self) {} }
