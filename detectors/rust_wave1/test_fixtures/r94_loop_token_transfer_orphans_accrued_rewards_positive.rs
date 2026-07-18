use soroban_sdk::{contract, contractimpl};
#[contract]
pub struct Pool;
#[contractimpl]
impl Pool {
    // BUG: _update mutates balance without settling rewards first
    pub fn _update(from: u64, to: u64, amount: u128) {
        self.balances[from] -= amount;
        self.balances[to] += amount;
        let _ = amount;
    }
}
// stub accessor to let regex match (self.balances[sender] -=)
impl Pool { fn noop(&mut self) {} }
