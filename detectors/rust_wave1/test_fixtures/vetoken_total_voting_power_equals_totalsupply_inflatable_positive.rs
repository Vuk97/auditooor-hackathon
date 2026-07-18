use std::collections::HashMap;

pub struct VeToken {
    locked_balances: HashMap<u64, u64>,
    lock_end_times: HashMap<u64, u64>,
    total_supply: u64,
}

impl VeToken {
    pub fn new() -> Self {
        Self {
            locked_balances: HashMap::new(),
            lock_end_times: HashMap::new(),
            total_supply: 0,
        }
    }

    pub fn mint_and_lock(&mut self, account: u64, amount: u64, lock_duration: u64, current_time: u64) {
        self.locked_balances.insert(account, amount);
        self.lock_end_times.insert(account, current_time + lock_duration);
        self.total_supply += amount;
    }

    fn get_voting_power_for_account(&self, account: u64, current_time: u64) -> u64 {
        let lock_end = match self.lock_end_times.get(&account) {
            Some(&end) => end,
            None => return 0,
        };
        let balance = self.locked_balances.get(&account).copied().unwrap_or(0);
        if current_time >= lock_end {
            return 0;
        }
        let remaining = lock_end.saturating_sub(current_time);
        balance.saturating_mul(remaining) / (4 * 365 * 24 * 60 * 60)
    }

    pub fn get_total_voting_power(&self, _current_time: u64) -> u64 {
        self.total_supply
    }

    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }
}

fn main() {
    let mut token = VeToken::new();
    let now = 1000u64;
    token.mint_and_lock(1, 1000, 365 * 24 * 60 * 60, now);
    token.mint_and_lock(2, 500, 180 * 24 * 60 * 60, now);
    
    let voting_power = token.get_total_voting_power(now);
    let supply = token.total_supply();
    assert_eq!(voting_power, supply, "BUG: voting power equals total supply, ignoring lock weights");
    println!("BUG: voting_power={} supply={} (should be weighted)", voting_power, supply);
}