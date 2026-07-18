use std::collections::HashMap;

pub struct RewardState {
    multipliers: HashMap<u64, u128>,
    user_reward_index: HashMap<u64, u128>,
    user_stakes: HashMap<u64, u128>,
}

impl RewardState {
    pub fn handle_balance_update(&mut self, user: u64, delta: u128) {
        if delta == 0 {
            self.multipliers.insert(user, 1);
            self.user_reward_index.insert(user, 0);
        }
    }

    pub fn stake(&mut self, user: u64, amount: u128) {
        self.user_stakes.insert(user, amount);
    }
}
