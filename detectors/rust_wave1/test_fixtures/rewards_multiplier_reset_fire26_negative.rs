use std::collections::HashMap;

pub struct RewardState {
    multipliers: HashMap<u64, u128>,
    user_reward_index: HashMap<u64, u128>,
    user_stakes: HashMap<u64, u128>,
}

impl RewardState {
    pub fn handle_balance_update(&mut self, user: u64, delta: u128) {
        self.require_user(user);
        if delta == 0 {
            self.multipliers.insert(user, 1);
            self.user_reward_index.insert(user, 0);
        }
    }

    pub fn stake(&mut self, user: u64, amount: u128) {
        let current_balance = self.user_stakes.get(&user).copied().unwrap_or(0);
        self.user_stakes.insert(user, current_balance + amount);
    }

    fn require_user(&self, _user: u64) {}
}
